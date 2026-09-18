#!/usr/bin/env python3
"""
PII Cleanup Preparation Script for the Test Project.

Reads the SQLite triage report produced/maintained via `scripts/pii_scanner.py`
(default: test_pii_scan_report.db, table pii_findings) and prepares the
artifacts needed to run `git filter-repo` in order to remove sensitive
personal data from the *entire* git history:

    - action == 'DELETE_FILE'  -> a path list for `git filter-repo
      --invert-paths --paths-from-file ...` (removes the whole file from
      every commit).
    - action == 'MODIFY_ENTRY' -> a rule file for `git filter-repo
      --replace-text ...` (replaces a literal string in every blob of the
      whole history, including the current HEAD).

IMPORTANT DESIGN DECISION (collision safety):
    git filter-repo's --replace-text performs a *global*, blind literal
    substring replacement across every blob in the whole repository - it has
    no notion of "this file" or "this line". Using the bare PII value (e.g.
    a ZIP code like "10587") as the search pattern is therefore dangerous:
    the very same literal value can legitimately occur elsewhere in the
    repository in findings that were triaged as IGNORE (verified for this
    report - short/generic values like ZIP codes and house numbers do
    collide). Replacing it globally would silently corrupt those unrelated,
    non-sensitive occurrences too.

    To avoid this, this script does NOT use the bare `value` as the replace
    pattern. Instead, it uses the full source line captured in the
    `context` column (marked with the ">>> " prefix by pii_scanner.py),
    which contains the surrounding key/quotes/tag and is therefore far more
    specific and much less likely to collide with unrelated content
    elsewhere in the repository.

IMPORTANT DISCOVERY FROM A DRY RUN (formatting drift across history):
    An initial dry run on a scratch mirror clone showed that some values
    (e.g. an IBAN) still remained reachable via `git log --all -S"<value>"`
    even after a literal, full-line replace-text rule was applied. Root
    cause: the file had been reformatted at some point in its history (e.g.
    a "prettier" commit changed leading indentation from spaces to tabs, or
    changed the indentation depth). A literal rule derived from the
    *current* file content only matches that one formatting variant; older
    historical blobs with different leading whitespace are not touched.

    To fix this, each rule is emitted in `regex:` mode with the *leading*
    whitespace captured as a group and reproduced in the replacement
    (`regex:([ \t]*)<escaped rest of line>==>\1<escaped patched rest of line>`).
    This matches the same line regardless of how many spaces/tabs of
    indentation precede it in any historical revision, while still requiring
    an exact match of everything else on the line (key, quotes, value, XML
    tag, etc.) for collision-safety. Residual risk: formatting drift *other*
    than leading indentation (e.g. spacing around ":" changed by a
    minifier/pretty-printer) is not covered by this and would need a
    per-value manual check (see the recommended `git log --all -S"<value>"`
    verification step after any dry run).

This script is intentionally a *preparation* tool only:
    - It never modifies the working repository.
    - It never runs `git filter-repo` against the real repository.
    - It never pushes or touches any remote.
    - The actual (destructive, history-rewriting) run must be performed
      manually, by a human, on a fresh mirror clone in a scratch directory,
      following the printed instructions - after a successful dry run and
      an agreed code freeze.

Usage:
    python3 scripts/prepare_pii_cleanup.py [--db PATH] [--out-dir PATH] [--repo-root PATH]

Exit codes:
    0  - all preconditions satisfied, artifacts written successfully
    1  - blocking data-quality issues found (see printed report)
    2  - usage / IO error
"""

import argparse
import re
import sqlite3
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

CONTEXT_MARKER = ">>> "


class PreparationError(Exception):
    """Raised for blocking data-quality problems that must be fixed in the DB first."""


def load_rows(db_path: Path) -> List[sqlite3.Row]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.execute(
            "SELECT id, file, line, field, value, replacement, context, action "
            "FROM pii_findings WHERE action IN ('DELETE_FILE', 'MODIFY_ENTRY', 'CHECK')"
        )
        return cur.fetchall()
    finally:
        conn.close()


def validate(rows: List[sqlite3.Row]) -> Tuple[List[sqlite3.Row], List[sqlite3.Row]]:
    """Validate preconditions. Returns (delete_rows, modify_rows) or raises PreparationError."""
    problems: List[str] = []

    check_rows = [r for r in rows if r["action"] == "CHECK"]
    if check_rows:
        check_files = sorted({r["file"] for r in check_rows})
        problems.append(
            f"{len(check_rows)} finding(s) with action=CHECK still pending across "
            f"{len(check_files)} file(s). All findings must be triaged to IGNORE, "
            f"DELETE_FILE or MODIFY_ENTRY before a history rewrite. "
            f"Affected files (first 20 shown): "
            + ", ".join(check_files[:20])
        )

    delete_rows = [r for r in rows if r["action"] == "DELETE_FILE"]
    modify_rows = [r for r in rows if r["action"] == "MODIFY_ENTRY"]

    delete_files = {r["file"] for r in delete_rows}
    modify_files = {r["file"] for r in modify_rows}
    conflicting = sorted(delete_files & modify_files)
    if conflicting:
        problems.append(
            "The following file(s) have BOTH DELETE_FILE and MODIFY_ENTRY findings, "
            "which is not allowed (a file is either deleted entirely or patched, not both): "
            + ", ".join(conflicting)
        )

    missing_replacement = [
        r for r in modify_rows if not (r["replacement"] and str(r["replacement"]).strip())
    ]
    if missing_replacement:
        problems.append(
            f"{len(missing_replacement)} MODIFY_ENTRY finding(s) have no (or empty) "
            f"'replacement' value set. Example ids: "
            + ", ".join(str(r["id"]) for r in missing_replacement[:20])
        )

    if problems:
        raise PreparationError("\n\n".join(f"- {p}" for p in problems))

    return delete_rows, modify_rows


def extract_marked_line(context: str) -> Optional[str]:
    """Extract the single line marked with '>>> ' from a multi-line context blob.

    Note: pii_scanner.py truncates very long context lines for readability, so this
    is only used as a *fallback* when the actual source file/line cannot be read
    from disk (e.g. the file no longer exists in the current working tree).
    """
    for raw_line in (context or "").splitlines():
        if raw_line.startswith(CONTEXT_MARKER):
            return raw_line[len(CONTEXT_MARKER):]
    return None


class SourceFileCache:
    """Caches file contents (split into lines) to avoid re-reading files per finding."""

    def __init__(self, repo_root: Path):
        self._repo_root = repo_root
        self._cache: Dict[str, Optional[List[str]]] = {}

    def get_line(self, file: str, line_no: int) -> Optional[str]:
        if file not in self._cache:
            path = self._repo_root / file
            try:
                # splitlines() (without keepends) correctly handles the last line
                # whether or not the file ends with a trailing newline.
                self._cache[file] = path.read_text(encoding="utf-8", errors="surrogateescape").splitlines()
            except OSError:
                self._cache[file] = None

        lines = self._cache[file]
        if lines is None or line_no < 1 or line_no > len(lines):
            return None
        return lines[line_no - 1]


def build_delete_paths(delete_rows: List[sqlite3.Row]) -> List[str]:
    return sorted({r["file"] for r in delete_rows})


def build_replace_rules(
    modify_rows: List[sqlite3.Row],
    source_cache: SourceFileCache,
) -> Tuple[List[Tuple[str, str]], List[str]]:
    """
    Build (search, replacement) literal line patterns for git filter-repo --replace-text.

    The *actual* source line is read from disk (preferred, exact) via `source_cache`;
    the truncated 'context' column is only used as a fallback when the file/line is not
    available (e.g. file already removed from the working tree).

    Findings are grouped by (file, line) first: several PII values can legitimately share
    the same physical source line (e.g. a whole customer record serialized as one long
    JSON line). All values found on that line are substituted together, producing a single
    replace rule per distinct original line - this avoids silently losing replacements when
    multiple findings map to the same line.
    """
    warnings: List[str] = []
    by_line: Dict[Tuple[str, int], List[sqlite3.Row]] = defaultdict(list)
    for r in modify_rows:
        by_line[(r["file"], r["line"])].append(r)

    rules: Dict[str, str] = {}

    for (file, line_no), group in by_line.items():
        disk_line = source_cache.get_line(file, line_no)
        context_line = extract_marked_line(group[0]["context"])

        # Prefer whichever candidate actually contains ALL values of this line group.
        # This guards against DB/working-tree drift (the recorded line number no longer
        # matching the current file content, e.g. because the file was edited after the
        # scan was run) - in that case the truncated 'context' marker line is still likely
        # correct even though the line number is not.
        candidates: List[Tuple[str, str]] = []
        if disk_line is not None:
            candidates.append((disk_line, "file"))
        if context_line is not None and context_line != disk_line:
            candidates.append((context_line, "context"))

        if not candidates:
            for r in group:
                warnings.append(
                    f"id={r['id']} file={file}:{line_no} - could not read source line from "
                    f"disk and no '{CONTEXT_MARKER}' line found in context, skipped"
                )
            continue

        values = [r["value"] for r in group]
        original_line, source = next(
            ((line, src) for line, src in candidates if all(v in line for v in values)),
            candidates[0],
        )
        if source == "context" and disk_line is not None:
            warnings.append(
                f"file={file}:{line_no} - recorded line number did not match the current "
                f"file content (possible DB/working-tree drift, e.g. file edited after the "
                f"scan ran); falling back to the (possibly truncated) context line instead. "
                f"Consider re-running pii_scanner.py to refresh line numbers."
            )

        patched_line = original_line
        applied_any = False
        for r in group:
            value = r["value"]
            replacement = r["replacement"]
            if value not in patched_line:
                warnings.append(
                    f"id={r['id']} file={file}:{line_no} - value {value!r} not found "
                    f"verbatim in {source} line, skipped for this finding "
                    f"(possible DB/working-tree drift - consider re-running pii_scanner.py)"
                )
                continue
            patched_line = patched_line.replace(value, replacement)
            applied_any = True

        if not applied_any:
            continue

        if original_line == patched_line:
            continue

        if original_line in rules and rules[original_line] != patched_line:
            warnings.append(
                f"file={file}:{line_no} - conflicting replacement already registered for the "
                f"same original line from a different file/location "
                f"({rules[original_line]!r} vs {patched_line!r}), keeping the first one"
            )
            continue

        rules[original_line] = patched_line

    return sorted(rules.items()), warnings


def find_collisions_with_ignored(
    conn: sqlite3.Connection,
    replace_rules: List[Tuple[str, str]],
    source_cache: SourceFileCache,
) -> List[str]:
    """
    Cross-check whether any of the derived search patterns (the actual source line) also
    occurs verbatim at an IGNORE-classified finding's line elsewhere. If so, a blind
    history-wide replace could unintentionally alter that unrelated, non-sensitive
    occurrence too.
    """
    collisions: List[str] = []
    cur = conn.execute("SELECT file, line, context FROM pii_findings WHERE action = 'IGNORE'")
    ignore_lines: Dict[str, List[str]] = defaultdict(list)
    for row in cur.fetchall():
        line = source_cache.get_line(row["file"], row["line"])
        if line is None:
            line = extract_marked_line(row["context"])
        if line is not None:
            ignore_lines[line].append(f"{row['file']}:{row['line']}")

    for search, _replacement in replace_rules:
        if search in ignore_lines:
            locations = ", ".join(ignore_lines[search][:10])
            collisions.append(
                f"Pattern {search!r} also occurs in {len(ignore_lines[search])} IGNORE-classified "
                f"finding(s), e.g. at: {locations}"
            )

    return collisions


def check_working_tree_occurrences(
    repo_root: Path, replace_rules: List[Tuple[str, str]]
) -> List[str]:
    """
    Best-effort sanity check: for each search pattern, count how many times it occurs
    literally in the current working tree (tracked files only) via `git grep -F -c`.
    Patterns occurring in more than 1 place are flagged for manual review, since
    --replace-text would touch all of them.
    """
    warnings: List[str] = []
    for search, _replacement in replace_rules:
        try:
            result = subprocess.run(
                ["git", "grep", "-F", "-c", search],
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (subprocess.SubprocessError, OSError) as exc:
            warnings.append(f"Could not run git grep for pattern {search!r}: {exc}")
            continue

        if result.returncode not in (0, 1):
            warnings.append(
                f"git grep failed for pattern {search!r}: {result.stderr.strip()}"
            )
            continue

        total_hits = 0
        for line in result.stdout.splitlines():
            # format: <path>:<count>
            try:
                total_hits += int(line.rsplit(":", 1)[1])
            except (IndexError, ValueError):
                continue

        if total_hits > 1:
            warnings.append(
                f"Pattern occurs {total_hits} time(s) in the current working tree, expected 1: "
                f"{search!r}"
            )

    return warnings


def build_regex_rule(original_line: str, patched_line: str) -> str:
    """
    Build a single git filter-repo --replace-text rule line in `regex:` mode that matches
    `original_line` regardless of its *leading* whitespace (spaces/tabs), reproducing
    whatever leading whitespace was actually present in the replacement. This guards
    against historical formatting drift (e.g. a "prettier"/reformatting commit that only
    changed indentation) causing older blob variants of the same line to be missed by a
    plain literal match. Everything after the leading whitespace is matched and replaced
    literally (escaped), preserving the collision-safety of using the full line as anchor.
    """
    ws_len = len(original_line) - len(original_line.lstrip(" \t"))
    rest_original = original_line[ws_len:]
    rest_patched = patched_line[ws_len:] if patched_line[:ws_len] == original_line[:ws_len] else patched_line.lstrip(" \t")

    pattern = r"([ \t]*)" + re.escape(rest_original)
    # `patched_line` never contains backslashes for our fixed replacement values, but escape
    # defensively since the replacement string is interpreted by re.sub (backslash-escapes).
    replacement = r"\1" + rest_patched.replace("\\", "\\\\")
    return f"regex:{pattern}==>{replacement}"


def write_outputs(
    out_dir: Path,
    delete_paths: List[str],
    replace_rules: List[Tuple[str, str]],
    collisions: List[str],
    tree_warnings: List[str],
    rule_warnings: List[str],
    distinct_values: List[str],
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)

    paths_file = out_dir / "paths_to_delete.txt"
    paths_file.write_text("\n".join(delete_paths) + ("\n" if delete_paths else ""), encoding="utf-8")

    verify_file = out_dir / "verify_history.sh"
    with verify_file.open("w", encoding="utf-8") as f:
        f.write(
            "#!/bin/sh\n"
            "# Mandatory post-rewrite verification (run inside the rewritten mirror clone).\n"
            "#\n"
            "# A dry run performed while building this tooling showed that some values can\n"
            "# still be reachable in older history even after --replace-text, when a file was\n"
            "# reformatted at some point (e.g. a 'prettier'/pretty-print commit changed a\n"
            "# value from being embedded in one long escaped line to its own separate line,\n"
            "# or vice versa) - a per-line replace rule cannot always match every historical\n"
            "# physical-line layout of the same logical value. This is a known, documented\n"
            "# git-filter-repo limitation; the upstream documentation explicitly prescribes\n"
            "# this exact iterative check-and-fix workflow:\n"
            "#   'If either of these commands turn up more sensitive data, then run\n"
            "#    additional git-filter-repo commands to clean up the necessary data\n"
            "#    before proceeding.'\n"
            "#\n"
            "# Usage: sh verify_history.sh   (run from within the rewritten *.git mirror)\n"
            "# Exit code is non-zero if any value is still found anywhere in history.\n"
            "#\n"
            "# NOTE: for short/generic values (e.g. ZIP codes, house numbers, phone number\n"
            "# fragments) a hit here can be a FALSE POSITIVE - the same literal digits may\n"
            "# legitimately occur elsewhere for unrelated, non-sensitive reasons (this was\n"
            "# already surfaced separately as a 'collision warning' in report.md while this\n"
            "# tooling was being validated). Cross-check each hit's commit/file against the\n"
            "# known collisions in report.md; only findings that are NOT already-known\n"
            "# collisions represent a genuine formatting-drift gap that needs an additional\n"
            "# --replace-text rule.\n"
            "set -e\n"
            "found=0\n"
        )
        for value in distinct_values:
            escaped = value.replace("'", "'\\''")
            f.write(
                f"output=$(git -c safe.bareRepository=all log --all --oneline -F -S'{escaped}' 2>&1) || "
                f"{{ echo \"ERROR: git log failed for value '{escaped}': $output\" >&2; exit 2; }}\n"
                f"if [ -n \"$output\" ]; then\n"
                f"  echo \"STILL PRESENT IN HISTORY: {escaped}\"\n"
                f"  echo \"$output\"\n"
                f"  found=1\n"
                f"fi\n"
            )
        f.write(
            "if [ \"$found\" -ne 0 ]; then\n"
            "  echo\n"
            "  echo 'One or more sensitive values are still reachable in history.'\n"
            "  echo 'Inspect the listed commits, derive additional --replace-text rules'\n"
            "  echo '(or --blob-callback logic) for the differing historical formatting,'\n"
            "  echo 'and re-run git filter-repo on a fresh mirror clone before pushing.'\n"
            "  exit 1\n"
            "fi\n"
            "echo 'No remaining occurrences of any MODIFY_ENTRY value found in history.'\n"
        )
    verify_file.chmod(0o755)

    rules_file = out_dir / "replace_rules.txt"
    with rules_file.open("w", encoding="utf-8") as f:
        for search, replacement in replace_rules:
            # regex mode: leading whitespace is matched flexibly and reproduced in the
            # replacement (see build_regex_rule) to be resilient against historical
            # reformatting/indentation drift, while still requiring an exact match of
            # everything else on the line for collision-safety.
            f.write(build_regex_rule(search, replacement) + "\n")

    report_file = out_dir / "report.md"
    with report_file.open("w", encoding="utf-8") as f:
        f.write("# PII Cleanup Preparation Report\n\n")
        f.write(f"- Files to delete entirely (DELETE_FILE): {len(delete_paths)}\n")
        f.write(f"- Distinct replace-text rules (MODIFY_ENTRY): {len(replace_rules)}\n\n")

        if rule_warnings:
            f.write("## Rule derivation warnings\n\n")
            f.write(
                "The following findings were skipped when deriving replace rules "
                "(need manual attention before the rewrite):\n\n"
            )
            for w in rule_warnings:
                f.write(f"- {w}\n")
            f.write("\n")

        if collisions:
            f.write("## Collision warnings (search pattern also found in IGNORE findings)\n\n")
            f.write(
                "These patterns, if used with --replace-text, would also modify content "
                "that was explicitly triaged as non-sensitive. Review and refine before "
                "the actual rewrite:\n\n"
            )
            for c in collisions:
                f.write(f"- {c}\n")
            f.write("\n")

        if tree_warnings:
            f.write("## Working-tree occurrence warnings\n\n")
            f.write(
                "Best-effort `git grep` sanity check against the current working tree "
                "(tracked files only). Patterns occurring more than once should be reviewed:\n\n"
            )
            for w in tree_warnings:
                f.write(f"- {w}\n")
            f.write("\n")

        if not collisions and not tree_warnings and not rule_warnings:
            f.write("No collision or derivation warnings detected.\n\n")

        f.write("## Next steps (manual, on a scratch mirror clone only)\n\n")
        f.write(
            "```bash\n"
            "# 1. Fresh mirror clone in a throwaway scratch directory (never the working repo!)\n"
            "git clone --mirror <origin-url> /path/to/scratch/test-mirror.git\n"
            "cd /path/to/scratch/test-mirror.git\n\n"
            "# 2. Combined rewrite: delete flagged files AND replace flagged literal lines\n"
            f"git filter-repo --invert-paths --paths-from-file {paths_file} \\\n"
            f"    --replace-text {rules_file}\n\n"
            "# 3. MANDATORY verification (per upstream git-filter-repo recommendation):\n"
            "#    a) re-run the PII scanner against a checkout of this rewritten mirror and\n"
            "#       confirm no DELETE_FILE/MODIFY_ENTRY findings remain, and that files\n"
            "#       listed under 'IGNORE' are textually unchanged;\n"
            f"#    b) run {verify_file} from inside the rewritten mirror clone - it checks\n"
            "#       every distinct MODIFY_ENTRY value with 'git log --all -S\"<value>\"' and\n"
            "#       fails if any is still reachable anywhere in history (this can happen if\n"
            "#       a file was reformatted at some point, e.g. pretty-printed, so the same\n"
            "#       value existed in a different physical-line layout in older history -\n"
            "#       in that case derive an additional --replace-text rule for that older\n"
            "#       layout and re-run step 2 on a fresh mirror clone).\n\n"
            "# 4. Only after successful verification AND an agreed code freeze with the team:\n"
            "git remote add origin <origin-url>\n"
            "git push --force origin 'refs/heads/*:refs/heads/*' 'refs/tags/*:refs/tags/*'\n\n"
            "# 5. Announce to the whole team: every local clone/fork must be re-cloned\n"
            "#    from scratch (not pulled/rebased). Recreate any open pull requests.\n"
            "```\n"
        )

    print(f"Wrote: {paths_file}")
    print(f"Wrote: {rules_file}")
    print(f"Wrote: {verify_file}")
    print(f"Wrote: {report_file}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "--db",
        default="test_pii_scan_report.db",
        help="Path to the PII scan SQLite report (default: test_pii_scan_report.db)",
    )
    parser.add_argument(
        "--out-dir",
        default="pii_cleanup",
        help="Directory to write the prepared artifacts into (default: ./pii_cleanup)",
    )
    parser.add_argument(
        "--repo-root",
        default=".",
        help="Repository root, used only for the best-effort working-tree collision check "
        "(default: current directory)",
    )
    parser.add_argument(
        "--skip-tree-check",
        action="store_true",
        help="Skip the (slower) git grep based working-tree occurrence check",
    )
    args = parser.parse_args()

    db_path = Path(args.db)
    if not db_path.is_file():
        print(f"Error: database file not found: {db_path}", file=sys.stderr)
        return 2

    rows = load_rows(db_path)

    try:
        delete_rows, modify_rows = validate(rows)
    except PreparationError as exc:
        print("Blocking data-quality issues found - fix the pii_findings table before proceeding:\n", file=sys.stderr)
        print(str(exc), file=sys.stderr)
        return 1

    delete_paths = build_delete_paths(delete_rows)
    source_cache = SourceFileCache(Path(args.repo_root))
    replace_rules, rule_warnings = build_replace_rules(modify_rows, source_cache)

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        collisions = find_collisions_with_ignored(conn, replace_rules, source_cache)
    finally:
        conn.close()

    tree_warnings: List[str] = []
    if not args.skip_tree_check:
        tree_warnings = check_working_tree_occurrences(Path(args.repo_root), replace_rules)

    distinct_values = sorted({r["value"] for r in modify_rows})

    write_outputs(
        Path(args.out_dir),
        delete_paths,
        replace_rules,
        collisions,
        tree_warnings,
        rule_warnings,
        distinct_values,
    )

    print(f"\n{len(delete_paths)} file(s) to delete, {len(replace_rules)} replace rule(s) derived.")
    if collisions or tree_warnings or rule_warnings:
        print(
            "Warnings were recorded in the report - review them before running git filter-repo.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
