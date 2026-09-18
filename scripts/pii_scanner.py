#!/usr/bin/env python3
"""
PII (Personally Identifiable Information) Scanner for the Test Project

Scans all project files for personally identifiable information and generates
a structured CSV report to assess whether test data or real production data is present.

Recognized PII fields:
    - Last name (lastName)
    - First name (firstName)
    - Street (street)
    - House number (houseNumber)
    - Postal code (zipCode/postalCode/zip/plz)
    - City (city)
    - Country (country)
    - Gender (gender)
    - Company name (companyName)
    - Email addresses
    - Phone numbers
    - Date of birth (birthDate/dateOfBirth)
    - IBAN (iban)
    - BIC (bic)
    - Bank account owner (bankAccountOwner)
    - Bank account number (bankAccountNumber)
    - Vehicle identification number / Fahrgestellnummer (vin), incl. context-free
      detection based on the standard 17-character VIN format (ISO 3779)

Recognized value/key formats:
    - JSON ("key": "value")
    - SQL literals and INSERT statements
    - YAML / Properties / INI (key: value / key=value, unquoted or quoted)
    - XML (<key>value</key>)
    - Java/Kotlin setter and builder method calls (.setFirstname("Max") / .firstName("Max"))
    - CSV files (header row is used to classify columns)
    - Context-free value patterns (email addresses, IBANs) regardless of the key name

Usage:
    python3 scripts/pii_scanner.py [project_root] [--csv]

By default, the parent directory of this script is used as the project root, and
the report is written to a SQLite database file (see OUTPUT_FILE_NAME). Pass
--csv to write a CSV report instead (see OUTPUT_CSV_FILE_NAME).

Each finding has an "Action" column (default: CHECK) that can be set to IGNORE,
DELETE_FILE or MODIFY_ENTRY to track triage decisions. Each finding also has a
"Replacement" column (default: empty) that can be filled in with a replacement
value when Action is set to MODIFY_ENTRY. When re-running the scan against an
existing SQLite report, previously set Action and Replacement values are
preserved for findings that are still present (matched by file, line, field
and value).

The "File" column contains paths relative to the scanned project_root.

Note: Directories such as test resource folders are intentionally NOT excluded or
treated as "safe". Real production data has been found copied into test fixtures
before, so everything is scanned and reported; the "Likely_Test_Data" column is
merely a hint for triage, never a filter. When in doubt, findings are reported
rather than suppressed (favoring recall over precision).
"""

import argparse
import csv
import json
import os
import re
import sqlite3
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ============================================================================
# Configuration
# ============================================================================

# Directories to ignore during scanning.
# Intentionally does NOT include test resource directories (e.g. src/test/resources) -
# real production data has been found copied into test fixtures before and must be
# reported like any other file.
IGNORE_DIRS = {
    '.git', '.idea', '.vscode', 'node_modules', 'target', 'build',
    'dist', 'out', '.gradle', '.m2', '__pycache__', '.cache',
    '.yarn', '.mvn', '.github'
}

# The name of the default output report file (SQLite database).
OUTPUT_FILE_NAME = 'test_pii_scan_report.db'
# The name of the alternative output report file (CSV, only used with --csv).
OUTPUT_CSV_FILE_NAME = 'test_pii_scan_report.csv'
# Files to ignore during scanning (e.g., this script's own output)
IGNORE_FILES = {
    OUTPUT_FILE_NAME,
    OUTPUT_CSV_FILE_NAME,
}

# Name of the SQLite table findings are stored in.
SQLITE_TABLE_NAME = 'pii_findings'

# The "Action" column tracks the triage decision for a finding. It defaults to
# CHECK (not yet triaged) and can be changed manually (e.g. directly in the
# SQLite database) to one of the other values below as findings are reviewed.
ACTION_DEFAULT = 'CHECK'
ACTION_VALUES = ('CHECK', 'IGNORE', 'DELETE_FILE', 'MODIFY_ENTRY')

# The "Replacement" column holds a free-text replacement value for a finding,
# to be filled in manually when Action is set to MODIFY_ENTRY. It defaults to
# an empty string and, like Action, is preserved across re-runs against an
# existing SQLite report.
REPLACEMENT_DEFAULT = ''

# File types to scan for PII
SEARCH_EXTENSIONS = {
    '.json', '.yaml', '.yml', '.xml', '.sql', '.properties',
    '.conf', '.cfg', '.ini', '.toml', '.tsv', '.txt', '.md',
    '.java', '.kt', '.groovy', '.scala', '.js', '.ts', '.jsx', '.tsx',
    '.html', '.jsp', '.ftl', '.csv', '.log'
}

# File extensions that get dedicated, format-aware scanning logic.
JSON_EXTENSIONS = {'.json'}
CSV_EXTENSIONS = {'.csv', '.tsv'}
SQL_EXTENSIONS = {'.sql'}

# Binary file types to skip
BINARY_EXTENSIONS = {
    '.class', '.jar', '.war', '.ear', '.zip', '.tar', '.gz', '.bz2',
    '.xz', '.7z', '.rar', '.pdf', '.doc', '.docx', '.xls', '.xlsx',
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.svg', '.ico', '.css',
    '.scss', '.less', '.woff', '.woff2', '.ttf', '.eot', '.db',
    '.sqlite', '.sqlite3', '.h2.db'
}

# Token sequences (see tokenize_key()) that identify a PII field by its key/setter name.
# Field names were cross-checked against real usage in the project (Java TOs/VOs, Lombok
# setters, and SQL data dumps) to cover naming variants actually found in the codebase,
# e.g. "zip" (not just "zipCode"), "houseNumber", bare "company", "statusUserFirstname",
# "bankAccountIBAN", "bankAccountBIC" and "bankAccountOwner".
FIELD_TOKEN_SEQUENCES: Dict[str, List[Tuple[str, ...]]] = {
    'lastName': [('last', 'name'), ('lastname',), ('nachname',)],
    'firstName': [('first', 'name'), ('firstname',), ('vorname',), ('given', 'name'), ('givenname',)],
    'street': [('street',), ('strasse',), ('straße',), ('address', 'line1'), ('addressline1',), ('road',)],
    'houseNumber': [('house', 'number'), ('housenumber',), ('hausnummer',)],
    'zipCode': [
        ('zip', 'code'), ('zipcode',), ('zip',),
        ('postal', 'code'), ('postalcode',), ('plz',), ('postcode',),
    ],
    'city': [('city',), ('ort',), ('town',), ('location',)],
    'country': [('country',), ('land',)],
    'gender': [('gender',), ('geschlecht',), ('sex',)],
    'companyName': [
        ('company', 'name'), ('companyname',), ('firma',), ('unternehmen',),
        ('org', 'name'), ('orgname',), ('organisation',), ('company',),
    ],
    'email': [('email',), ('e', 'mail'), ('mail',)],
    'phone': [('phone',), ('telefon',), ('mobile',), ('handy',), ('cell', 'phone'), ('cellphone',)],
    'birthDate': [
        ('birth', 'date'), ('birthdate',), ('date', 'of', 'birth'),
        ('dateofbirth',), ('geburtsdatum',),
    ],
    'iban': [('iban',)],
    'bic': [('bic',), ('swift',)],
    'bankAccountOwner': [
        ('bank', 'account', 'owner'), ('bankaccountowner',), ('kontoinhaber',), ('account', 'owner'),
    ],
    'bankAccountNumber': [
        ('bank', 'account', 'number'), ('bankaccountnumber',), ('kontonummer',),
        ('account', 'number'), ('accountnumber',),
    ],
    'vin': [
        ('vin',), ('fin',), ('chassis', 'number'), ('chassisnumber',), ('fahrgestellnummer',),
    ],
}

# Fields whose values are checked with format-specific (context-free) regexes,
# independent of the surrounding key name, because their structure is distinctive
# enough to detect reliably even without a matching key (e.g. an email address
# embedded under an unrelated key, or an IBAN mentioned in a comment).
#
# IBAN candidates additionally require a valid IBAN country code AND a valid mod-97
# checksum (see _looks_like_valid_iban()) before being reported without a matching key
# name. Plain format matching ("2 letters + 2 digits + alnum") is NOT enough: 17-char
# VINs/FINs (e.g. "VF37B9HF0FJ521498") and random hex/pseudonymized IDs (e.g.
# "CD77CC1C7EF33DB") coincidentally satisfy that shape but are not IBANs.
EMAIL_VALUE_PATTERN = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
IBAN_VALUE_PATTERN = re.compile(r'\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b')

# ISO 3166-1 alpha-2 codes of countries/territories that actually issue IBANs.
# Used to reject values that merely look like an IBAN by chance (VINs, hex IDs, ...).
IBAN_COUNTRY_CODES = {
    'AD', 'AE', 'AL', 'AT', 'AZ', 'BA', 'BE', 'BG', 'BH', 'BR', 'BY', 'CH', 'CR',
    'CY', 'CZ', 'DE', 'DK', 'DO', 'EE', 'EG', 'ES', 'FI', 'FO', 'FR', 'GB', 'GE',
    'GI', 'GL', 'GR', 'GT', 'HR', 'HU', 'IE', 'IL', 'IQ', 'IS', 'IT', 'JO', 'KW',
    'KZ', 'LB', 'LC', 'LI', 'LT', 'LU', 'LV', 'LY', 'MC', 'MD', 'ME', 'MK', 'MR',
    'MT', 'MU', 'NL', 'NO', 'PK', 'PL', 'PS', 'PT', 'QA', 'RO', 'RS', 'SA', 'SC',
    'SD', 'SE', 'SI', 'SK', 'SM', 'ST', 'SV', 'TL', 'TN', 'TR', 'UA', 'VA', 'VG',
    'XK',
}


def _looks_like_valid_iban(value: str) -> bool:
    """Validates a candidate IBAN string: correct length/shape, a known IBAN country
    code, and a valid ISO 7064 mod-97 checksum. This is what actually distinguishes a
    real IBAN from an incidental look-alike (VIN, hex ID, ...)."""
    compact = re.sub(r'\s+', '', value).upper()
    if not re.fullmatch(r'[A-Z]{2}\d{2}[A-Z0-9]{11,30}', compact):
        return False
    if compact[:2] not in IBAN_COUNTRY_CODES:
        return False
    rearranged = compact[4:] + compact[:4]
    try:
        numeric = ''.join(str(int(ch, 36)) for ch in rearranged)
    except ValueError:
        return False
    return int(numeric) % 97 == 1


# Context-free VIN/FIN (Fahrgestellnummer) detection: standard 17-character VIN
# (ISO 3779), which excludes the letters I, O and Q (to avoid confusion with 1/0),
# and must contain at least one letter and one digit (rules out plain numeric IDs).
VIN_VALUE_PATTERN = re.compile(
    r'\b(?=[A-HJ-NPR-Z0-9]{17}\b)(?=[A-HJ-NPR-Z0-9]*[0-9])(?=[A-HJ-NPR-Z0-9]*[A-HJ-NPR-Z])'
    r'[A-HJ-NPR-Z0-9]{17}\b'
)

# Known placeholder/example IBANs frequently copy-pasted from tutorials or banking docs.
KNOWN_TEST_IBANS = {
    'DE89370400440532013000',  # classic German banking-tutorial example (Bundesbank)
    'GB29NWBK60161331926819',  # classic UK example IBAN
    'DE68210501700012345678',
}

# Known test data patterns for classification (applied to all PII fields).
# Note: does NOT include short country-code prefixes like "de"/"us"/"uk" - those
# would falsely match unrelated values that merely start with those letters (e.g.
# the name "Detlef", an email "detlef@...", or a German IBAN starting with "DE").
# Country codes are only checked via COUNTRY_TEST_DATA_INDICATORS, and only for
# the 'country' field.
TEST_DATA_INDICATORS = [
    re.compile(r'^(?:test|demo|example|sample|dummy|fake|mock)', re.IGNORECASE),
    re.compile(r'^(?:john|jane|max|mustermann|musterfrau|doe|smith|jones)', re.IGNORECASE),
    re.compile(r'^(?:main[_\-]?street|hauptstraße|hauptstr\.?|dummensweg|teststraße)', re.IGNORECASE),
    re.compile(r'^(?:12345|00000|99999|00001|10115|10117)$'),
    re.compile(r'^(?:acme|test[_\-]?corp|example[_\-]?inc|dummy[_\-]?company)', re.IGNORECASE),
]

# Test data patterns that only make sense for the 'country' field itself.
COUNTRY_TEST_DATA_INDICATORS = [
    re.compile(r'^(?:germany|deutschland|de|us|usa|uk|gb|france|frankreich)$', re.IGNORECASE),
]


# ============================================================================
# Data Structures
# ============================================================================

@dataclass
class PiiFinding:
    """Represents a single PII finding in a scanned file."""
    file_path: str
    line_number: int
    field_name: str
    value: str
    context: str
    data_type: str  # 'structured' or 'unstructured'
    is_likely_test_data: bool = True


# ============================================================================
# Key classification (token-based)
# ============================================================================

def tokenize_key(key: str) -> List[str]:
    """Splits a camelCase/PascalCase/snake_case/kebab-case identifier into lowercase tokens.

    This is used instead of naive substring matching so that short field names like
    "city", "ort" or "sex" don't accidentally match inside unrelated words (e.g. the
    German word for city, "ort", is a substring of many unrelated words such as
    "Import" or "Sortierung"). Only whole camelCase/snake_case "words" are compared.

    Examples:
        "firstName"            -> ["first", "name"]
        "statusUserFirstname"  -> ["status", "user", "firstname"]
        "bankAccountIBAN"      -> ["bank", "account", "iban"]
        "zip_code"             -> ["zip", "code"]
        "setFirstname"         -> ["set", "firstname"]
    """
    if not key:
        return []
    # Boundary between a lowercase letter/digit and a following uppercase letter.
    s = re.sub(r'(?<=[a-z0-9])(?=[A-Z])', '_', key)
    # Boundary between an uppercase acronym and a following capitalized word, e.g. "IBANValue".
    s = re.sub(r'(?<=[A-Z])(?=[A-Z][a-z])', '_', s)
    tokens = re.split(r'[_\-.\s]+', s)
    return [t.lower() for t in tokens if t]


def classify_field(key: str) -> Optional[str]:
    """Determines the PII field type based on a key/setter/tag name.

    Matches whole tokens or contiguous token sequences (see tokenize_key), so
    compound identifiers such as "statusUserFirstname", "bankAccountIBAN" or
    "setFirstname" are recognized, not just exact/prefix matches.
    """
    tokens = tokenize_key(key)
    if not tokens:
        return None

    for field_name, sequences in FIELD_TOKEN_SEQUENCES.items():
        for seq in sequences:
            n = len(seq)
            if n == 0 or n > len(tokens):
                continue
            for i in range(len(tokens) - n + 1):
                if tuple(tokens[i:i + n]) == seq:
                    return field_name
    return None


# ============================================================================
# Generic key/value extraction for non-JSON text formats
# ============================================================================

# "key": "value"  (JSON-in-text, JS/TS object literals, SQL string literals)
KV_QUOTED_KEY = re.compile(r'"([A-Za-z][\w\-]*)"\s*[:=]\s*"([^"]*)"')
# key = "value" / key: "value"  (Java field assignment, YAML with quoted value, .properties)
KV_BARE_KEY_QUOTED_VALUE = re.compile(r'(?<![\w."\'])([A-Za-z][\w\-]*)\s*[:=]\s*"([^"]*)"')
# .setFirstname("Max") / .firstName("Max")  (Java/Kotlin setters and builder-style calls)
KV_JAVA_METHOD_CALL = re.compile(r'\.([A-Za-z][\w]*)\s*\(\s*"([^"]*)"')
# <firstName>Max</firstName>  (XML)
KV_XML_TAG = re.compile(r'<([A-Za-z][\w\-]*)(?:\s[^>]*)?>\s*([^<>]+?)\s*</\1\s*>')
# firstName: Max   /   firstName=Max   (unquoted YAML / .properties / .ini, whole line)
KV_BARE_LINE = re.compile(r'^([A-Za-z][\w\-.]*)\s*[:=]\s*([^"\'{\[\s][^#]*?)\s*(?:#.*)?$')


def extract_kv_pairs(raw_line: str) -> List[Tuple[str, str]]:
    """Extracts all (key, value) candidate pairs from a single line, covering
    JSON/SQL/Java/YAML/Properties/XML style syntax. Irrelevant pairs are filtered
    later via classify_field(), so over-matching here is acceptable and intentional
    (favoring recall over precision)."""
    pairs: List[Tuple[str, str]] = []
    pairs.extend(KV_QUOTED_KEY.findall(raw_line))
    pairs.extend(KV_BARE_KEY_QUOTED_VALUE.findall(raw_line))
    pairs.extend(KV_JAVA_METHOD_CALL.findall(raw_line))
    pairs.extend((k, v.strip()) for k, v in KV_XML_TAG.findall(raw_line))

    stripped = raw_line.strip()
    m = KV_BARE_LINE.match(stripped)
    if m:
        pairs.append((m.group(1), m.group(2).strip()))

    # Deduplicate while preserving order (multiple patterns can match the same construct).
    return list(dict.fromkeys(pairs))


# ============================================================================
# Helper Functions
# ============================================================================

def normalize_value(field_name: str, value: str) -> str:
    """Normalizes a field value to a standard English/machine-readable format."""
    if not value or value.strip() in ('', 'null', 'None', 'undefined'):
        return ''

    # Strip surrounding quotes
    value = value.strip('"\'')

    # Normalize gender values to English
    if field_name.lower() == 'gender':
        gender_map = {
            'MALE': 'MALE', 'FEMALE': 'FEMALE', 'NON_BINARY': 'NON_BINARY',
            'OTHER': 'OTHER', 'M': 'MALE', 'F': 'FEMALE', 'W': 'FEMALE',
            'MÄNNLICH': 'MALE', 'WEIBLICH': 'FEMALE', 'DIVERS': 'NON_BINARY'
        }
        return gender_map.get(value.upper(), value)

    # Normalize country values to ISO codes
    if field_name.lower() == 'country':
        country_map = {
            'DEUTSCHLAND': 'DE', 'GERMANY': 'DE', 'USA': 'US', 'UK': 'GB',
            'GB': 'GB', 'FRANCE': 'FR', 'FRANKREICH': 'FR', 'ITALY': 'IT',
            'ITALIEN': 'IT', 'SPAIN': 'ES', 'SPANIEN': 'ES'
        }
        return country_map.get(value.upper(), value)

    # Normalize IBAN/BIC to a compact, uppercase representation
    if field_name.lower() in ('iban', 'bic'):
        return re.sub(r'\s+', '', value).upper()

    return value


def _is_test_iban_or_bic(value: str) -> bool:
    """Detects well-known placeholder IBANs/BICs and obviously fake patterns."""
    compact = re.sub(r'\s+', '', value).upper()
    if compact in KNOWN_TEST_IBANS:
        return True
    if re.search(r'(0{6,}|X{4,}|1234567|TEST)', compact):
        return True
    return False


def is_likely_test_data(field_name: str, value: str) -> bool:
    """Determines whether a value is likely test/fake data.

    Note: this classification is only a triage hint (used for the console summary
    and the "Likely_Test_Data" column) - it never suppresses a finding from the CSV
    report. When unsure, this function is intentionally biased towards "not test
    data" (i.e. towards flagging as a potential real-data finding), since missing
    real personal data is considered worse than a false alarm on test data.
    """
    if not value or value.strip() in ('', 'null', 'None', 'undefined'):
        return True

    # Very short values (< 2 chars) are likely test data
    if len(value.strip()) < 2:
        return True

    field_key = field_name.lower()

    # IBAN/BIC/bank account values: checked *before* the generic indicators below,
    # since e.g. a German IBAN starting with "DE" would otherwise incorrectly match
    # the generic country-code test pattern ("de") and be misclassified as test data.
    if field_key in ('iban', 'bic', 'bankaccountnumber'):
        return _is_test_iban_or_bic(value)

    # VINs/FINs: only obviously fake placeholders (repeated characters, "TEST", ...)
    # count as test data. A real-looking VIN in a deletion/migration SQL script is
    # very likely to be a genuine vehicle identification number.
    if field_key == 'vin':
        compact = value.strip().upper()
        if re.search(r'(.)\1{5,}', compact) or 'TEST' in compact or 'XXXXX' in compact:
            return True
        return False

    # Country codes/names are only checked against the dedicated country pattern list
    # (short codes like "de"/"us" must not leak into other fields, see comment above).
    if field_key == 'country':
        return any(pattern.search(value) for pattern in COUNTRY_TEST_DATA_INDICATORS)

    # Check against known test data patterns
    for pattern in TEST_DATA_INDICATORS:
        if pattern.search(value):
            return True

    # Postal codes with exactly 5 digits may be real
    if field_key in ('zipcode', 'postalcode', 'plz'):
        if re.match(r'^\d{5}$', value):
            return False  # Real postal codes typically have 5 digits

    # Email addresses are likely real unless domain contains test keywords
    if field_key == 'email':
        if '@' in value:
            domain = value.split('@')[1]
            if any(test in domain for test in ['test', 'example', 'demo', 'dummy']):
                return True
            return False

    # Longer values (> 20 chars) are more likely to be real data
    if len(value.strip()) > 20:
        return False

    return False


def extract_context(lines: List[str], line_idx: int, context_lines: int = 3) -> str:
    """Extracts surrounding context lines around a given line index."""
    start = max(0, line_idx - context_lines)
    end = min(len(lines), line_idx + context_lines + 1)

    context_parts = []
    for i in range(start, end):
        marker = '>>>' if i == line_idx else '   '
        line_content = lines[i].strip()[:200]  # Limit line length
        context_parts.append(f"{marker} {line_content}")

    return '\n'.join(context_parts)


def find_context_free_matches(text: str) -> List[Tuple[str, str]]:
    """Finds context-free PII value patterns (email, IBAN, VIN/FIN) anywhere in a
    string, independent of any surrounding key name. Returns (field_name, matched_value)
    pairs for the actual matched substring only - never the whole surrounding text.

    IBAN candidates are additionally validated (country code + mod-97 checksum) so
    that VINs/FINs and random hex/pseudonymized IDs that merely share the coarse
    "2 letters + 2 digits + alnum" shape are not misreported as IBANs.
    """
    results: List[Tuple[str, str]] = []
    for match in EMAIL_VALUE_PATTERN.finditer(text):
        results.append(('email', match.group(0)))
    for match in IBAN_VALUE_PATTERN.finditer(text):
        if _looks_like_valid_iban(match.group(0)):
            results.append(('iban', match.group(0)))
    for match in VIN_VALUE_PATTERN.finditer(text):
        results.append(('vin', match.group(0)))
    return results


def find_line_in_json(lines: List[str], last_segment: str, search_from: int) -> int:
    """Attempts to locate the line number of a JSON key, searching forward from
    search_from so that repeated keys (e.g. multiple customers in an array, each
    with their own "firstName") are attributed to distinct, increasing line
    numbers instead of all collapsing onto the first occurrence in the file."""
    for i in range(search_from, len(lines)):
        if f'"{last_segment}"' in lines[i]:
            return i

    # Fallback: wrap around and search from the beginning (handles out-of-order edge cases).
    for i in range(0, search_from):
        if f'"{last_segment}"' in lines[i]:
            return i

    return 0


# ============================================================================
# Scanner Functions
# ============================================================================

def scan_json_data(data: Any, file_path: Path, lines: List[str],
                   findings: List[PiiFinding], path: str, cursor: Dict[str, int]):
    """Recursively scans JSON data structures for PII fields."""
    if isinstance(data, dict):
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key

            # Check if the key matches a known PII field
            field_name = classify_field(key)

            if field_name and isinstance(value, str) and value.strip():
                # Find the line in the original JSON file, searching forward from the
                # last match so repeated keys in arrays get distinct line numbers.
                line_idx = find_line_in_json(lines, key, cursor['pos'])
                cursor['pos'] = line_idx + 1
                context = extract_context(lines, line_idx)

                is_test = is_likely_test_data(field_name, value)

                findings.append(PiiFinding(
                    file_path=str(file_path),
                    line_number=line_idx + 1,
                    field_name=field_name,
                    value=value,
                    context=context,
                    data_type='structured',
                    is_likely_test_data=is_test
                ))
            elif isinstance(value, str) and value.strip():
                # Even if the key itself isn't recognized, check the value against
                # context-free patterns (e.g. an email, IBAN or VIN stored under an
                # unrelated key name). Only the matched substring is reported, never
                # the entire (possibly huge, e.g. a serialized raw payload) field value.
                for cf_field, cf_value in find_context_free_matches(value):
                    line_idx = find_line_in_json(lines, key, cursor['pos'])
                    cursor['pos'] = line_idx + 1
                    context = extract_context(lines, line_idx)
                    is_test = is_likely_test_data(cf_field, cf_value)
                    findings.append(PiiFinding(
                        file_path=str(file_path),
                        line_number=line_idx + 1,
                        field_name=cf_field,
                        value=cf_value,
                        context=context,
                        data_type='structured',
                        is_likely_test_data=is_test
                    ))

            # Recursively scan nested structures
            scan_json_data(value, file_path, lines, findings, current_path, cursor)

    elif isinstance(data, list):
        for i, item in enumerate(data):
            scan_json_data(item, file_path, lines, findings, f"{path}[{i}]", cursor)


def scan_json_file(file_path: Path, findings: List[PiiFinding]):
    """Scans a JSON file for personally identifiable information."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

        # Try to parse as JSON first
        try:
            data = json.loads(content)
            lines = content.split('\n')
            scan_json_data(data, file_path, lines, findings, '', {'pos': 0})
        except json.JSONDecodeError:
            # Fallback: scan line by line as plain text
            _scan_text_file(file_path, findings)
    except Exception as e:
        print(f"  Error reading {file_path}: {e}", file=sys.stderr)


def _scan_lines_generic(file_path: Path, lines: List[str], findings: List[PiiFinding], data_type: str):
    """Scans arbitrary text lines for PII using key/value extraction (JSON-in-text,
    SQL, YAML, Properties, XML, Java setters/builders) plus context-free value
    patterns (email addresses, IBANs) that are detected regardless of key name."""
    for line_idx, line in enumerate(lines):
        seen_values_on_line = set()

        for key, value in extract_kv_pairs(line):
            if not value.strip():
                continue
            field_name = classify_field(key)
            if not field_name:
                continue
            if (field_name, value) in seen_values_on_line:
                continue
            seen_values_on_line.add((field_name, value))

            context = extract_context(lines, line_idx)
            is_test = is_likely_test_data(field_name, value)

            findings.append(PiiFinding(
                file_path=str(file_path),
                line_number=line_idx + 1,
                field_name=field_name,
                value=value,
                context=context,
                data_type=data_type,
                is_likely_test_data=is_test
            ))

        # Context-free patterns: found independent of any recognized key name
        # (email addresses, validated IBANs, VIN/FIN vehicle identification numbers -
        # e.g. as plain positional literals in a SQL INSERT/DELETE statement).
        for cf_field, value in find_context_free_matches(line):
            if (cf_field, value) in seen_values_on_line:
                continue
            seen_values_on_line.add((cf_field, value))

            context = extract_context(lines, line_idx)
            is_test = is_likely_test_data(cf_field, value)

            findings.append(PiiFinding(
                file_path=str(file_path),
                line_number=line_idx + 1,
                field_name=cf_field,
                value=value,
                context=context,
                data_type=data_type,
                is_likely_test_data=is_test
            ))


def scan_sql_file(file_path: Path, findings: List[PiiFinding]):
    """Scans SQL files for PII in INSERT statements, embedded JSON payloads and data literals."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        _scan_lines_generic(file_path, lines, findings, data_type='structured')
    except Exception as e:
        print(f"  Error reading {file_path}: {e}", file=sys.stderr)


def _scan_text_file(file_path: Path, findings: List[PiiFinding]):
    """Scans a generic text file (YAML, XML, Properties, Java/Kotlin, Markdown, ...)
    for PII patterns."""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
        _scan_lines_generic(file_path, lines, findings, data_type='unstructured')
    except Exception as e:
        print(f"  Error reading {file_path}: {e}", file=sys.stderr)


def scan_csv_file(file_path: Path, findings: List[PiiFinding]):
    """Scans a CSV/TSV file for PII. The header row is used to classify columns;
    matching columns are then checked row by row."""
    delimiter = '\t' if file_path.suffix.lower() == '.tsv' else ','
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore', newline='') as f:
            reader = csv.reader(f, delimiter=delimiter)
            rows = list(reader)

        if not rows:
            return

        header = rows[0]
        column_fields = {idx: classify_field(col) for idx, col in enumerate(header)}
        column_fields = {idx: field for idx, field in column_fields.items() if field}

        if not column_fields:
            # No recognizable header - still check content for context-free patterns
            # like embedded email addresses or IBANs.
            _scan_lines_generic(file_path, [delimiter.join(r) for r in rows], findings, data_type='structured')
            return

        for row_idx, row in enumerate(rows[1:], start=2):  # header is line 1
            for col_idx, field_name in column_fields.items():
                if col_idx >= len(row):
                    continue
                value = row[col_idx].strip()
                if not value:
                    continue

                preview_cols = row[:6]
                context = f">>> {delimiter.join(preview_cols)}"[:200]
                is_test = is_likely_test_data(field_name, value)

                findings.append(PiiFinding(
                    file_path=str(file_path),
                    line_number=row_idx,
                    field_name=field_name,
                    value=value,
                    context=context,
                    data_type='structured',
                    is_likely_test_data=is_test
                ))
    except Exception as e:
        print(f"  Error reading {file_path}: {e}", file=sys.stderr)


def should_scan_file(file_path: Path) -> bool:
    """Determines whether a file should be scanned for PII."""
    # Skip binary files
    if file_path.suffix.lower() in BINARY_EXTENSIONS:
        return False

    # Skip ignored files (e.g., this script's own output)
    if file_path.name in IGNORE_FILES:
        return False

    # Skip files inside ignored directories
    for part in file_path.parts:
        if part in IGNORE_DIRS:
            return False

    # Only scan files with relevant extensions
    if file_path.suffix.lower() not in SEARCH_EXTENSIONS:
        return False

    return True


# ============================================================================
# Main Scan Function
# ============================================================================

def scan_project(project_root: Path) -> List[PiiFinding]:
    """Scans the entire project for personally identifiable information."""
    findings = []
    project_root = project_root.resolve()

    print(f"🔍 Scanning project: {project_root}")
    print(f"   Ignored directories: {', '.join(sorted(IGNORE_DIRS))}")
    print(f"   Scanned file types: {', '.join(sorted(SEARCH_EXTENSIONS))}")
    print()

    file_count = 0

    for root, dirs, files in os.walk(project_root):
        # Remove ignored directories from traversal
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]

        for filename in files:
            file_path = Path(root) / filename

            if should_scan_file(file_path):
                file_count += 1

                # Determine file type and scan accordingly
                suffix = file_path.suffix.lower()

                if suffix in JSON_EXTENSIONS:
                    scan_json_file(file_path, findings)
                elif suffix in SQL_EXTENSIONS:
                    scan_sql_file(file_path, findings)
                elif suffix in CSV_EXTENSIONS:
                    scan_csv_file(file_path, findings)
                else:
                    _scan_text_file(file_path, findings)

    print(f"✅ Scanned {file_count} files")
    print(f"📊 Found {len(findings)} PII occurrence(s)")

    # Report paths relative to project_root instead of absolute paths.
    for finding in findings:
        finding.file_path = str(Path(finding.file_path).resolve().relative_to(project_root))

    return findings


# ============================================================================
# Report Generation
# ============================================================================

def generate_csv_report(findings: List[PiiFinding], output_file: Path):
    """Generates a CSV report of all PII findings."""

    # Sort findings by file path and line number
    sorted_findings = sorted(findings, key=lambda f: (f.file_path, f.line_number))

    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)

        # Write header row
        writer.writerow([
            'File',
            'Line',
            'Field',
            'Value',
            'Normalized_Value',
            'Data_Type',
            'Likely_Test_Data',
            'Context',
            'Action',
            'Replacement'
        ])

        for finding in sorted_findings:
            normalized_value = normalize_value(finding.field_name, finding.value)

            writer.writerow([
                finding.file_path,
                finding.line_number,
                finding.field_name,
                finding.value,
                normalized_value,
                finding.data_type,
                'Yes' if finding.is_likely_test_data else 'No',
                finding.context.replace('\n', ' | '),
                ACTION_DEFAULT,
                REPLACEMENT_DEFAULT
            ])

    print(f"\n📄 CSV report saved: {output_file}")


def _load_existing_triage_data(output_file: Path) -> Dict[Tuple[str, int, str, str], Tuple[str, str]]:
    """Reads Action and Replacement values from a pre-existing SQLite report, keyed by
    (file, line, field, value), so that triage decisions made by a human
    between scanner runs are not lost when the report is regenerated.

    Returns an empty dict if the file doesn't exist yet or isn't a compatible
    SQLite report (e.g. from an older scanner version).
    """
    existing_data: Dict[Tuple[str, int, str, str], Tuple[str, str]] = {}

    if not output_file.exists():
        return existing_data

    try:
        conn = sqlite3.connect(str(output_file))
        try:
            try:
                cursor = conn.execute(
                    f"SELECT file, line, field, value, action, replacement FROM {SQLITE_TABLE_NAME}"
                )
                for file_path, line_number, field_name, value, action, replacement in cursor.fetchall():
                    existing_data[(file_path, line_number, field_name, value)] = (
                        action, replacement if replacement is not None else REPLACEMENT_DEFAULT
                    )
            except sqlite3.OperationalError:
                # Older report without the 'replacement' column yet - fall back to
                # reading just 'action' and default the replacement value.
                cursor = conn.execute(
                    f"SELECT file, line, field, value, action FROM {SQLITE_TABLE_NAME}"
                )
                for file_path, line_number, field_name, value, action in cursor.fetchall():
                    existing_data[(file_path, line_number, field_name, value)] = (action, REPLACEMENT_DEFAULT)
        finally:
            conn.close()
    except sqlite3.DatabaseError:
        # Not a valid/compatible SQLite report yet - start fresh.
        pass

    return existing_data


def generate_sqlite_report(findings: List[PiiFinding], output_file: Path):
    """Generates a SQLite report of all PII findings.

    If a report already exists at output_file, previously set 'action' and
    'replacement' values are preserved for findings that are still present
    (matched by file, line, field and value), so manual triage work isn't
    lost on re-scans.
    """

    existing_data = _load_existing_triage_data(output_file)

    # Sort findings by file path and line number
    sorted_findings = sorted(findings, key=lambda f: (f.file_path, f.line_number))

    conn = sqlite3.connect(str(output_file))
    try:
        conn.execute(f"DROP TABLE IF EXISTS {SQLITE_TABLE_NAME}")
        conn.execute(f"""
            CREATE TABLE {SQLITE_TABLE_NAME} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file TEXT NOT NULL,
                line INTEGER NOT NULL,
                field TEXT NOT NULL,
                value TEXT NOT NULL,
                normalized_value TEXT,
                data_type TEXT,
                likely_test_data BOOLEAN,
                context TEXT,
                action TEXT NOT NULL DEFAULT '{ACTION_DEFAULT}'
                    CHECK (action IN ({", ".join(f"'{v}'" for v in ACTION_VALUES)})),
                replacement TEXT
            )
        """)

        rows = []
        for finding in sorted_findings:
            normalized_value = normalize_value(finding.field_name, finding.value)
            key = (finding.file_path, finding.line_number, finding.field_name, finding.value)
            action, replacement = existing_data.get(key, (ACTION_DEFAULT, None))

            rows.append((
                finding.file_path,
                finding.line_number,
                finding.field_name,
                finding.value,
                normalized_value,
                finding.data_type,
                finding.is_likely_test_data,
                finding.context,
                action,
                replacement
            ))

        conn.executemany(
            f"""INSERT INTO {SQLITE_TABLE_NAME}
                (file, line, field, value, normalized_value, data_type,
                 likely_test_data, context, action, replacement)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows
        )
        conn.commit()
    finally:
        conn.close()

    print(f"\n📄 SQLite report saved: {output_file}")


def generate_summary(findings: List[PiiFinding]):
    """Prints a summary of all PII findings to the console."""

    if not findings:
        print("\n✅ No personally identifiable information found!")
        return

    # Count findings by field type
    field_counts = {}
    for finding in findings:
        field_counts[finding.field_name] = field_counts.get(finding.field_name, 0) + 1

    # Count test data vs potentially real data
    test_data_count = sum(1 for f in findings if f.is_likely_test_data)
    real_data_count = len(findings) - test_data_count

    # Unique files with PII
    unique_files = set(f.file_path for f in findings)

    print("\n" + "=" * 80)
    print("📊 SUMMARY OF FINDINGS")
    print("=" * 80)

    print(f"\n📁 Affected files: {len(unique_files)}")
    print(f"🔍 Total findings: {len(findings)}")
    print(f"✅ Likely test data: {test_data_count} ({test_data_count / len(findings) * 100:.1f}%)")
    print(f"⚠️  Potentially real data: {real_data_count} ({real_data_count / len(findings) * 100:.1f}%)")

    print("\n📋 Findings by field type:")
    for field, count in sorted(field_counts.items(), key=lambda x: -x[1]):
        print(f"    {field:20s}: {count}")

    # Highlight potentially real data
    if real_data_count > 0:
        print("\n⚠️  POTENTIALLY REAL PERSONAL DATA:")
        print("-" * 80)

        for finding in findings:
            if not finding.is_likely_test_data:
                print(f"\n    📁 {finding.file_path}:{finding.line_number}")
                print(f"    🔍 Field: {finding.field_name}")
                print(f"    💾 Value: {finding.value}")
                print(f"    📝 Context:")
                for line in finding.context.split('\n'):
                    print(f"       {line}")

    print("\n" + "=" * 80)


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    """Main entry point for the PII scanner."""
    parser = argparse.ArgumentParser(
        description="Scans the project for personally identifiable information (PII)."
    )
    parser.add_argument(
        'project_root',
        nargs='?',
        default=None,
        help="Project root directory to scan (default: parent directory of this script)"
    )
    parser.add_argument(
        '--csv',
        action='store_true',
        help=f"Write the report as CSV ({OUTPUT_CSV_FILE_NAME}) instead of the "
             f"default SQLite database ({OUTPUT_FILE_NAME})"
    )
    args = parser.parse_args()

    # Determine project root directory
    if args.project_root:
        project_root = Path(args.project_root).resolve()
    else:
        project_root = Path(__file__).parent.parent.resolve()

    print("🔍 PII Scanner - Personally Identifiable Information Detector")
    print("=" * 80)

    # Scan the project
    findings = scan_project(project_root)

    # Generate the report
    if args.csv:
        output_file = project_root / OUTPUT_CSV_FILE_NAME
        generate_csv_report(findings, output_file)
    else:
        output_file = project_root / OUTPUT_FILE_NAME
        generate_sqlite_report(findings, output_file)

    # Print summary to console
    generate_summary(findings)

    # Return non-zero exit code if potentially real data was found
    return 0 if not any(not f.is_likely_test_data for f in findings) else 1


if __name__ == '__main__':
    sys.exit(main())
