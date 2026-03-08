#!/usr/bin/env python3
"""
1Password (.1pux) to Apple Passwords Converter

Takes a .1pux export file and produces Apple Passwords-ready CSV
along with reference files for items that need manual handling.

Usage:
  python3 onepass_to_apple.py export.1pux                   # full run
  python3 onepass_to_apple.py export.1pux -o ./my_output    # custom output dir
  python3 onepass_to_apple.py export.1pux --dry-run         # preview only, no passwords written
  python3 onepass_to_apple.py export.1pux --per-vault       # one import CSV per vault
  python3 onepass_to_apple.py export.1pux --interactive      # choose vaults to include
  python3 onepass_to_apple.py export.1pux --secure-delete    # overwrite files with zeros before delete

Output includes:
  - Apple Passwords import CSV (with extra fields merged into Notes)
  - Separated credit cards, software licenses, OTP review files
  - files/ folder with all attachments (license files, documents) from 1Password
  - Full analysis report (duplicates, password health, category breakdown)

100% offline — no network calls, no APIs, no dependencies beyond Python 3.6+.
"""

import json
import sys
import csv
import os
import argparse
import hashlib
import zipfile
import shutil
import tempfile
from pathlib import Path
from datetime import datetime
from collections import OrderedDict, Counter
from urllib.parse import urlparse


# ── Config ──────────────────────────────────────────────────────────────────

APPLE_COLUMNS = ["Title", "URL", "Username", "Password", "Notes", "OTPAuth"]
METADATA_FIELDS = {"url_0", "uuid", "state", "createdAt", "updatedAt",
                   "categoryUuid", "tags", "favIndex", "_vault_name"}

# 1Password category UUIDs
CATEGORY_MAP = {
    "001": "Login",
    "002": "Credit Card",
    "003": "Secure Note",
    "004": "Identity",
    "005": "Software License",
    "006": "Bank Account",
    "100": "Database",
    "101": "Driver License",
    "102": "Outdoor License",
    "103": "Membership",
    "104": "Passport",
    "105": "Rewards Program",
    "106": "Social Security Number",
    "107": "Wireless Router",
    "108": "Server",
    "109": "Email Account",
    "110": "API Credential",
    "111": "Medical Record",
    "112": "SSH Key",
    "113": "Passkey",
}

PASSKEY_KEYWORDS = {"passkey", "fido2", "webauthn", "discoverable credential",
                    "passkeys"}

CREDIT_CARD_MARKERS = {"cardholder name", "number", "expiry date",
                       "verification number", "credit limit", "type"}


# ── Step 1: Extract .1pux ───────────────────────────────────────────────────

def extract_1pux(pux_path, out_dir, dry_run=False):
    """Extract .1pux (zip), return parsed JSON, and copy attachments."""
    pux_path = Path(pux_path)
    if not pux_path.exists():
        print(f"Error: File '{pux_path}' not found.")
        sys.exit(1)

    tmp_dir = tempfile.mkdtemp(prefix="1pux_")
    try:
        with zipfile.ZipFile(pux_path, 'r') as zf:
            zf.extractall(tmp_dir)
    except zipfile.BadZipFile:
        print(f"Error: '{pux_path}' is not a valid zip/1pux file.")
        sys.exit(1)

    data_file = Path(tmp_dir) / "export.data"
    if not data_file.exists():
        candidates = list(Path(tmp_dir).rglob("export.data"))
        if not candidates:
            print(f"Error: No 'export.data' found inside '{pux_path}'.")
            sys.exit(1)
        data_file = candidates[0]

    with open(data_file, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Copy attachments from files/ folder if present
    files_dir = Path(tmp_dir) / "files"
    attachment_count = 0
    if files_dir.exists() and files_dir.is_dir():
        attachments = list(files_dir.rglob("*"))
        attachment_files = [f for f in attachments if f.is_file()]
        attachment_count = len(attachment_files)

        if attachment_files and not dry_run:
            dest_files = out_dir / "files"
            if dest_files.exists():
                shutil.rmtree(dest_files)
            shutil.copytree(files_dir, dest_files)
            print(f"[Step 1] Copied {attachment_count} attachment(s) "
                  f"to {dest_files}/")
        elif attachment_files and dry_run:
            print(f"[Step 1] Found {attachment_count} attachment(s) "
                  f"(not copied — dry run)")
    else:
        print(f"[Step 1] No files/ folder found in .1pux "
              f"(no attachments)")

    shutil.rmtree(tmp_dir, ignore_errors=True)
    print(f"[Step 1] Extracted and parsed '{pux_path.name}'")
    return data, attachment_count


# ── Step 2: Extract items from all vaults ───────────────────────────────────

def extract_all_items(data):
    """Walk accounts -> vaults -> items and return flat list with vault info."""
    all_items = []
    vault_summary = []

    accounts = data.get("accounts", [])
    for account in accounts:
        account_name = account.get("attrs", {}).get("accountName", "Unknown")
        vaults = account.get("vaults", [])

        for vault in vaults:
            vault_attrs = vault.get("attrs", {})
            vault_name = vault_attrs.get("name", "Unknown")
            items = vault.get("items", [])

            vault_summary.append({
                "account": account_name,
                "vault": vault_name,
                "item_count": len(items)
            })

            for item in items:
                item["_vault_name"] = vault_name
                item["_account_name"] = account_name
                all_items.append(item)

    print(f"[Step 2] Extracted {len(all_items)} items from "
          f"{len(vault_summary)} vault(s):")
    for vs in vault_summary:
        print(f"         {vs['account']} / {vs['vault']}: "
              f"{vs['item_count']} items")

    return all_items, vault_summary


# ── Step 2b: Interactive vault selection ────────────────────────────────────

def interactive_vault_filter(items, vault_summary):
    """Prompt user to select which vaults to include."""
    print("\n--- Vault Selection ---")
    for idx, vs in enumerate(vault_summary):
        print(f"  [{idx + 1}] {vs['account']} / {vs['vault']} "
              f"({vs['item_count']} items)")
    print(f"  [A] All vaults")
    print()

    choice = input("Enter vault numbers to include (comma-separated, "
                   "or A for all): ").strip()

    if choice.upper() == 'A' or not choice:
        print("  -> Including all vaults")
        return items, vault_summary

    try:
        indices = [int(x.strip()) - 1 for x in choice.split(",")]
    except ValueError:
        print("  -> Invalid input, including all vaults")
        return items, vault_summary

    selected_vaults = set()
    selected_summary = []
    for i in indices:
        if 0 <= i < len(vault_summary):
            selected_vaults.add(vault_summary[i]["vault"])
            selected_summary.append(vault_summary[i])

    if not selected_vaults:
        print("  -> No valid selection, including all vaults")
        return items, vault_summary

    filtered = [item for item in items
                if item.get("_vault_name") in selected_vaults]

    print(f"  -> Selected {len(filtered)} items from "
          f"{len(selected_vaults)} vault(s)")
    return filtered, selected_summary


# ── Step 3: Filter active items ─────────────────────────────────────────────

def filter_active(items):
    """Keep only active items, report state breakdown."""
    states = Counter(item.get("state", "MISSING") for item in items)
    active = [item for item in items if item.get("state") == "active"]

    print(f"[Step 3] Filtered to {len(active)} active items:")
    for state, count in sorted(states.items(), key=lambda x: -x[1]):
        marker = " <-" if state == "active" else ""
        print(f"         {state}: {count}{marker}")

    return active, states


# ── Step 4: Flatten to CSV rows ─────────────────────────────────────────────

def extract_value_from_field(value_obj):
    if not isinstance(value_obj, dict):
        return str(value_obj) if value_obj else ""
    for key in ['totp', 'string', 'concealed', 'date', 'monthYear',
                'address', 'phone', 'email', 'url']:
        if key in value_obj:
            return str(value_obj[key])
    return json.dumps(value_obj)


def unix_to_readable(timestamp):
    if not timestamp:
        return ""
    try:
        return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(timestamp)


def flatten_item(item):
    flat = OrderedDict()

    overview = item.get('overview', {})
    flat['Title'] = overview.get('title', '')

    primary_url = overview.get('url', '')
    if not primary_url and overview.get('urls'):
        primary_url = (overview['urls'][0].get('url', '')
                       if overview['urls'] else '')
    flat['URL'] = primary_url

    username = ""
    password = ""
    for field in item.get('details', {}).get('loginFields', []):
        if field.get('designation') == 'username':
            username = field.get('value', '')
        elif field.get('designation') == 'password':
            password = field.get('value', '')
    flat['Username'] = username
    flat['Password'] = password
    flat['Notes'] = item.get('notesPlain',
                             item.get('details', {}).get('notesPlain', ''))

    otpauth = ""
    sections = item.get('details', {}).get('sections', [])
    for section in sections:
        for field in section.get('fields', []):
            value_obj = field.get('value', {})
            if isinstance(value_obj, dict) and 'totp' in value_obj:
                otpauth = value_obj['totp']
                break
        if otpauth:
            break
    flat['OTPAuth'] = otpauth

    urls = overview.get('urls', [])
    for idx, url_obj in enumerate(urls):
        flat[f'url_{idx}'] = url_obj.get('url', '')

    flat['uuid'] = item.get('uuid', '')
    flat['state'] = item.get('state', '')
    flat['createdAt'] = unix_to_readable(item.get('createdAt'))
    flat['updatedAt'] = unix_to_readable(item.get('updatedAt'))
    flat['categoryUuid'] = item.get('categoryUuid', '')
    tags = overview.get('tags', [])
    flat['tags'] = ', '.join(tags) if tags else ''
    flat['favIndex'] = item.get('favIndex', '')
    flat['_vault_name'] = item.get('_vault_name', '')

    for si, section in enumerate(sections):
        flat[f'section_{si}_title'] = section.get('title', '')
        flat[f'section_{si}_name'] = section.get('name', '')
        for fi, field in enumerate(section.get('fields', [])):
            flat[f'section_{si}_field_{fi}_title'] = field.get('title', '')
            flat[f'section_{si}_field_{fi}_id'] = field.get('id', '')
            flat[f'section_{si}_field_{fi}_value'] = \
                extract_value_from_field(field.get('value'))

    return flat


def flatten_all(items):
    flattened = []
    for idx, item in enumerate(items):
        try:
            flattened.append(flatten_item(item))
        except Exception as e:
            print(f"  Warning: Skipped item {idx}: {e}")
    print(f"[Step 4] Flattened {len(flattened)} items")
    return flattened


# ── Step 5: Analysis ────────────────────────────────────────────────────────

def detect_duplicates(flattened):
    """Find items with same URL domain + Username (likely duplicates)."""
    seen = {}  # (domain, username) -> list of titles
    duplicates = []

    for row in flattened:
        url = (row.get("URL", "") or "").strip()
        username = (row.get("Username", "") or "").strip()
        if not url or not username:
            continue

        try:
            domain = urlparse(url).netloc.lower()
            if domain.startswith("www."):
                domain = domain[4:]
        except Exception:
            domain = url.lower()

        key = (domain, username.lower())
        if key not in seen:
            seen[key] = []
        seen[key].append({
            "title": row.get("Title", ""),
            "vault": row.get("_vault_name", ""),
            "uuid": row.get("uuid", ""),
            "url": url,
        })

    for key, items in seen.items():
        if len(items) > 1:
            duplicates.append({
                "domain": key[0],
                "username": key[1],
                "count": len(items),
                "items": items
            })

    duplicates.sort(key=lambda x: -x["count"])
    return duplicates


def analyze_passwords(flattened):
    """Check for weak, short, and reused passwords (no network calls)."""
    password_hash_map = {}  # hash -> list of titles
    empty_passwords = []
    short_passwords = []  # < 8 chars

    for row in flattened:
        title = row.get("Title", "")
        password = row.get("Password", "") or ""

        if not password:
            empty_passwords.append(title)
            continue

        if len(password) < 8:
            short_passwords.append({"title": title, "length": len(password)})

        pw_hash = hashlib.sha256(password.encode()).hexdigest()
        if pw_hash not in password_hash_map:
            password_hash_map[pw_hash] = []
        password_hash_map[pw_hash].append(title)

    reused = []
    for pw_hash, titles in password_hash_map.items():
        if len(titles) > 1:
            reused.append({"count": len(titles), "items": titles})
    reused.sort(key=lambda x: -x["count"])

    return {
        "empty": empty_passwords,
        "short": short_passwords,
        "reused": reused,
    }


def classify_by_category(flattened):
    """Classify items using 1Password categoryUuid."""
    categories = Counter()
    for row in flattened:
        cat_id = (row.get("categoryUuid", "") or "").strip()
        cat_name = CATEGORY_MAP.get(cat_id, f"Unknown ({cat_id})")
        categories[cat_name] += 1
    return categories


def detect_passkeys(raw_items):
    """Detect passkey items from raw JSON (before flattening).

    Passkeys are identified by:
    - categoryUuid '113' (Passkey type)
    - presence of 'passkey' field in item details
    - passkey-related keywords in field titles or values
    """
    passkey_items = []

    for item in raw_items:
        title = item.get("overview", {}).get("title", "")
        url = item.get("overview", {}).get("url", "")
        cat_id = item.get("categoryUuid", "")
        vault = item.get("_vault_name", "")
        uuid = item.get("uuid", "")
        detected_by = None

        # Check category UUID
        if cat_id == "113":
            detected_by = "category"

        # Check for passkey field in details
        details = item.get("details", {})
        if not detected_by:
            # Check loginFields for passkey type
            for field in details.get("loginFields", []):
                field_type = str(field.get("type", "")).lower()
                field_name = str(field.get("name", "")).lower()
                field_desg = str(field.get("designation", "")).lower()
                if any(kw in val for kw in PASSKEY_KEYWORDS
                       for val in [field_type, field_name, field_desg]):
                    detected_by = "loginField"
                    break

        # Check sections for passkey references
        if not detected_by:
            for section in details.get("sections", []):
                for field in section.get("fields", []):
                    field_title = str(field.get("title", "")).lower()
                    field_id = str(field.get("id", "")).lower()
                    value_obj = field.get("value", {})
                    value_str = ""
                    if isinstance(value_obj, dict):
                        value_str = json.dumps(value_obj).lower()
                    else:
                        value_str = str(value_obj).lower()

                    if any(kw in val for kw in PASSKEY_KEYWORDS
                           for val in [field_title, field_id, value_str]):
                        detected_by = "sectionField"
                        break
                if detected_by:
                    break

        # Check overview title/tags for passkey mention
        if not detected_by:
            overview_text = json.dumps(item.get("overview", {})).lower()
            if any(kw in overview_text for kw in PASSKEY_KEYWORDS):
                detected_by = "overview"

        if detected_by:
            passkey_items.append({
                "title": title,
                "url": url,
                "vault": vault,
                "uuid": uuid,
                "detected_by": detected_by,
            })

    return passkey_items


# ── Step 6: Segregate and produce Apple import ──────────────────────────────

def get_section_field_titles(row, headers):
    return [(row.get(c, "") or "").strip()
            for c in headers
            if c.startswith("section_") and c.endswith("_title")
            and (row.get(c, "") or "").strip()]


def get_section_field_data(row, headers):
    pairs = []
    for col in headers:
        if not (col.startswith("section_") and col.endswith("_value")):
            continue
        val = (row.get(col, "") or "").strip()
        if not val:
            continue
        title_col = col.replace("_value", "_title")
        title = (row.get(title_col, "") or "").strip()
        if not title:
            id_col = col.replace("_value", "_id")
            title = (row.get(id_col, "") or "").strip() or col
        pairs.append((title, val))
    return pairs


def get_extra_urls(row, headers):
    return [(row.get(c, "") or "").strip()
            for c in headers
            if c.startswith("url_") and c != "url_0"
            and (row.get(c, "") or "").strip()]


def is_credit_card(row, field_titles):
    """Detect credit cards by category UUID or field heuristics."""
    cat_id = (row.get("categoryUuid", "") or "").strip()
    if cat_id == "002":
        return True
    lower = {t.lower() for t in field_titles}
    return len(lower & CREDIT_CARD_MARKERS) >= 3


def is_software_license(row, field_titles):
    """Detect software licenses by category UUID or field heuristics."""
    cat_id = (row.get("categoryUuid", "") or "").strip()
    if cat_id == "005":
        return True
    lower = {t.lower() for t in field_titles}
    license_markers = {"license key", "licensed to", "version",
                       "registered email"}
    return len(lower & license_markers) >= 2


def has_otp_in_sections(field_titles):
    return any(t.lower() == "one-time password" for t in field_titles)


def merge_into_notes(existing_notes, section_data, extra_urls):
    parts = []
    if existing_notes:
        parts.append(existing_notes)
    if section_data:
        parts.append("--- 1Password Custom Fields ---")
        for title, value in section_data:
            parts.append(f"{title}: {value}")
    if extra_urls:
        parts.append("--- Additional URLs ---")
        parts.extend(extra_urls)
    return "\n".join(parts)


def segregate_and_export(flattened, out_dir, dry_run=False, per_vault=False):
    """Classify items and write all output files."""
    all_cols = OrderedDict()
    for item in flattened:
        for k in item:
            all_cols[k] = None
    headers = list(all_cols.keys())

    credit_cards = []
    software_licenses = []
    extra_urls_only = []
    otp_review = []
    extra_fields_ref = []
    final_import = []
    vault_imports = {}  # vault_name -> list of import rows

    for row in flattened:
        field_titles = get_section_field_titles(row, headers)
        section_data = get_section_field_data(row, headers)
        extra_urls = get_extra_urls(row, headers)
        has_section = len(section_data) > 0
        has_extra_url = len(extra_urls) > 0
        vault_name = row.get("_vault_name", "Default")

        # Credit cards — separate, exclude from import
        if is_credit_card(row, field_titles):
            credit_cards.append(row)
            continue

        # Software licenses — separate, exclude from import
        if is_software_license(row, field_titles):
            software_licenses.append(row)
            continue

        if has_otp_in_sections(field_titles):
            otp_review.append(row)

        if has_extra_url and not has_section:
            extra_urls_only.append(row)

        if has_section:
            extra_fields_ref.append(row)

        existing_notes = (row.get("Notes", "") or "").strip()
        merged_notes = merge_into_notes(existing_notes, section_data,
                                        extra_urls)

        import_row = OrderedDict()
        import_row["Title"] = row.get("Title", "")
        import_row["URL"] = row.get("URL", "")
        import_row["Username"] = row.get("Username", "")
        import_row["Password"] = row.get("Password", "")
        import_row["Notes"] = merged_notes
        import_row["OTPAuth"] = row.get("OTPAuth", "")
        final_import.append(import_row)

        if per_vault:
            if vault_name not in vault_imports:
                vault_imports[vault_name] = []
            vault_imports[vault_name].append(import_row)

    counts = {
        "total_flattened": len(flattened),
        "credit_cards": len(credit_cards),
        "software_licenses": len(software_licenses),
        "final_import": len(final_import),
        "extra_fields_merged": len(extra_fields_ref),
        "extra_urls_only": len(extra_urls_only),
        "otp_review": len(otp_review),
    }

    if dry_run:
        print(f"[Step 6] DRY RUN — no files written")
    else:
        def write_full(name, rows):
            path = out_dir / name
            with open(path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=headers)
                writer.writeheader()
                writer.writerows(rows)

        write_full("all_fields_flat.csv", flattened)
        write_full("credit_cards.csv", credit_cards)
        write_full("software_licenses.csv", software_licenses)
        write_full("extra_urls_only.csv", extra_urls_only)
        write_full("otp_review.csv", otp_review)
        write_full("extra_fields_reference.csv", extra_fields_ref)

        with open(out_dir / "apple_passwords_import.csv", 'w', newline='',
                  encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=APPLE_COLUMNS)
            writer.writeheader()
            writer.writerows(final_import)

        # Per-vault import files
        if per_vault and vault_imports:
            vault_dir = out_dir / "per_vault"
            vault_dir.mkdir(exist_ok=True)
            for vault_name, rows in vault_imports.items():
                safe_name = "".join(
                    c if c.isalnum() or c in (' ', '-', '_') else '_'
                    for c in vault_name
                ).strip()
                fname = f"apple_import_{safe_name}.csv"
                with open(vault_dir / fname, 'w', newline='',
                          encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=APPLE_COLUMNS)
                    writer.writeheader()
                    writer.writerows(rows)
            counts["per_vault_files"] = len(vault_imports)

        print(f"[Step 6] Segregated and exported:")

    print(f"         apple_passwords_import.csv  — "
          f"{counts['final_import']} items")
    print(f"         credit_cards.csv             — "
          f"{counts['credit_cards']} items")
    print(f"         software_licenses.csv        — "
          f"{counts['software_licenses']} items")
    print(f"         extra_fields_reference.csv   — "
          f"{counts['extra_fields_merged']} items")
    print(f"         extra_urls_only.csv          — "
          f"{counts['extra_urls_only']} items")
    print(f"         otp_review.csv               — "
          f"{counts['otp_review']} items")

    if per_vault and vault_imports:
        print(f"         per_vault/                   — "
              f"{len(vault_imports)} vault file(s)")

    return counts, credit_cards, software_licenses


# ── Secure delete ───────────────────────────────────────────────────────────

def secure_delete_dir(dir_path):
    """Overwrite all files in directory with zeros, then delete."""
    dir_path = Path(dir_path)
    if not dir_path.exists():
        return

    files = list(dir_path.rglob("*"))
    for f in files:
        if f.is_file():
            try:
                size = f.stat().st_size
                with open(f, 'wb') as fh:
                    fh.write(b'\x00' * size)  # pass 1: zeros
                    fh.flush()
                    os.fsync(fh.fileno())
                with open(f, 'wb') as fh:
                    fh.write(os.urandom(size))  # pass 2: random
                    fh.flush()
                    os.fsync(fh.fileno())
                with open(f, 'wb') as fh:
                    fh.write(b'\x00' * size)  # pass 3: zeros
                    fh.flush()
                    os.fsync(fh.fileno())
                f.unlink()
            except Exception as e:
                print(f"  Warning: Could not securely delete {f}: {e}")
                f.unlink(missing_ok=True)

    # Remove empty directories
    for d in sorted(files, reverse=True):
        if d.is_dir():
            try:
                d.rmdir()
            except OSError:
                pass
    try:
        dir_path.rmdir()
    except OSError:
        pass


# ── Report ──────────────────────────────────────────────────────────────────

def generate_report(pux_path, vault_summary, state_counts, counts,
                    categories, duplicates, pw_analysis, per_vault,
                    attachment_count=0, passkey_items=None):
    """Generate the summary report text."""
    lines = []
    lines.append("=" * 60)
    lines.append("1PASSWORD -> APPLE PASSWORDS CONVERSION REPORT")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Source: {pux_path.name}")
    lines.append("=" * 60)

    # Vaults
    lines.append("\nVAULTS:")
    for vs in vault_summary:
        lines.append(f"  {vs['account']} / {vs['vault']}: "
                     f"{vs['item_count']} items")

    # State breakdown
    lines.append("\nSTATE BREAKDOWN:")
    for state, count in sorted(state_counts.items(), key=lambda x: -x[1]):
        lines.append(f"  {state}: {count}")

    # Category breakdown
    lines.append("\nCATEGORY BREAKDOWN:")
    for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
        lines.append(f"  {cat}: {count}")

    # Output files
    lines.append("\nOUTPUT FILES:")
    lines.append(f"  apple_passwords_import.csv  — "
                 f"{counts['final_import']} items (IMPORT THIS)")
    lines.append(f"  credit_cards.csv             — "
                 f"{counts['credit_cards']} items")
    lines.append(f"  software_licenses.csv        — "
                 f"{counts['software_licenses']} items")
    lines.append(f"  extra_fields_reference.csv   — "
                 f"{counts['extra_fields_merged']} items")
    lines.append(f"  extra_urls_only.csv          — "
                 f"{counts['extra_urls_only']} items")
    lines.append(f"  otp_review.csv               — "
                 f"{counts['otp_review']} items")
    lines.append(f"  all_fields_flat.csv          — "
                 f"{counts['total_flattened']} items")
    if per_vault and counts.get("per_vault_files"):
        lines.append(f"  per_vault/                   — "
                     f"{counts['per_vault_files']} vault file(s)")
    if attachment_count > 0:
        lines.append(f"  files/                       — "
                     f"{attachment_count} attachment(s) "
                     f"(license files, documents)")
    else:
        lines.append(f"  files/                       — "
                     f"no attachments found")
    if passkey_items:
        lines.append(f"  passkeys_manual.csv          — "
                     f"{len(passkey_items)} passkey(s) "
                     f"(re-enrollment checklist)")

    # Passkeys
    if passkey_items:
        lines.append(f"\nPASSKEYS: {len(passkey_items)} detected "
                     f"(CANNOT be auto-migrated)")
        lines.append("-" * 40)
        lines.append("Passkeys are cryptographic credentials that cannot be "
                     "exported or transferred.")
        lines.append("You must re-enroll each passkey in Apple Passwords "
                     "by logging into the site.")
        lines.append("")
        for pk in passkey_items:
            vault_info = f" [vault: {pk['vault']}]" if pk['vault'] else ""
            lines.append(f"  - {pk['title']}: {pk['url']}{vault_info}")
    else:
        lines.append("\nPASSKEYS: None detected")

    # Duplicates
    if duplicates:
        lines.append(f"\nDUPLICATES DETECTED: {len(duplicates)} group(s)")
        lines.append("-" * 40)
        for dup in duplicates:
            lines.append(f"\n  {dup['domain']} / {dup['username']} "
                         f"({dup['count']} copies):")
            for item in dup['items']:
                vault_info = f" [vault: {item['vault']}]" \
                    if item['vault'] else ""
                lines.append(f"    - {item['title']}{vault_info}")
    else:
        lines.append("\nDUPLICATES: None detected")

    # Password health
    lines.append(f"\nPASSWORD HEALTH:")
    lines.append("-" * 40)
    lines.append(f"  Empty passwords:  {len(pw_analysis['empty'])}")
    lines.append(f"  Short (< 8 char): {len(pw_analysis['short'])}")
    lines.append(f"  Reused passwords: {len(pw_analysis['reused'])} group(s)")

    if pw_analysis['short']:
        lines.append("\n  Short passwords:")
        for item in pw_analysis['short'][:20]:
            lines.append(f"    - {item['title']} ({item['length']} chars)")
        if len(pw_analysis['short']) > 20:
            lines.append(f"    ... and "
                         f"{len(pw_analysis['short']) - 20} more")

    if pw_analysis['reused']:
        lines.append("\n  Reused passwords:")
        for group in pw_analysis['reused'][:15]:
            titles = ", ".join(group['items'][:5])
            extra = f" +{len(group['items']) - 5} more" \
                if len(group['items']) > 5 else ""
            lines.append(f"    - {group['count']}x: {titles}{extra}")
        if len(pw_analysis['reused']) > 15:
            lines.append(f"    ... and "
                         f"{len(pw_analysis['reused']) - 15} more groups")

    if pw_analysis['empty']:
        lines.append("\n  Empty passwords:")
        for title in pw_analysis['empty'][:20]:
            lines.append(f"    - {title}")
        if len(pw_analysis['empty']) > 20:
            lines.append(f"    ... and "
                         f"{len(pw_analysis['empty']) - 20} more")

    lines.append("\n" + "=" * 60)
    lines.append("REMINDER: Delete all output files after import — "
                 "they contain plaintext passwords!")
    if pw_analysis['reused']:
        lines.append("ACTION: Change reused passwords after migrating "
                     "to Apple Passwords.")
    lines.append("=" * 60)

    return "\n".join(lines)


# ── Main ────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Convert 1Password .1pux export to Apple Passwords CSV",
        epilog="100%% offline — no network, no APIs, no dependencies "
               "beyond Python 3.6+."
    )
    parser.add_argument("input", help="Path to .1pux export file")
    parser.add_argument("-o", "--output",
                        help="Output directory "
                             "(default: <input_stem>_output)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview report only — no password-containing "
                             "files written")
    parser.add_argument("--per-vault", action="store_true",
                        help="Generate one import CSV per vault "
                             "(in per_vault/ subdirectory)")
    parser.add_argument("--interactive", action="store_true",
                        help="Interactively choose which vaults to include")
    parser.add_argument("--secure-delete", action="store_true",
                        help="After confirmation, overwrite output files "
                             "with zeros and delete")

    args = parser.parse_args()
    pux_path = Path(args.input)

    # Handle --secure-delete mode
    if args.secure_delete:
        target_dir = Path(args.output) if args.output else Path(
            pux_path.stem + "_output")
        if not target_dir.exists():
            print(f"Error: Directory '{target_dir}' does not exist.")
            sys.exit(1)
        print(f"\nThis will securely delete ALL files in: {target_dir}/")
        print("Files will be overwritten with zeros and random data "
              "before deletion.")
        confirm = input("Type YES to confirm: ").strip()
        if confirm != "YES":
            print("Aborted.")
            sys.exit(0)
        secure_delete_dir(target_dir)
        print(f"Securely deleted: {target_dir}/")
        sys.exit(0)

    out_dir = Path(args.output) if args.output else Path(
        pux_path.stem + "_output")
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'=' * 60}")
    print(f"1Password (.1pux) -> Apple Passwords Converter")
    print(f"{'=' * 60}")
    print(f"Input:  {pux_path}")
    print(f"Output: {out_dir}/")
    if args.dry_run:
        print(f"Mode:   DRY RUN (no password files will be written)")
    print()

    # Step 1: Extract
    data, attachment_count = extract_1pux(pux_path, out_dir,
                                          dry_run=args.dry_run)

    # Step 2: Extract items
    all_items, vault_summary = extract_all_items(data)

    # Step 2b: Interactive vault selection
    if args.interactive:
        all_items, vault_summary = interactive_vault_filter(
            all_items, vault_summary)

    # Save raw items (skip in dry run)
    if not args.dry_run:
        with open(out_dir / "raw_all_items.json", 'w',
                  encoding='utf-8') as f:
            json.dump(all_items, f, indent=2)

    # Step 3: Filter active
    active_items, state_counts = filter_active(all_items)

    if not args.dry_run:
        with open(out_dir / "active_items.json", 'w',
                  encoding='utf-8') as f:
            json.dump(active_items, f, indent=2)

    # Step 4: Flatten
    flattened = flatten_all(active_items)

    # Step 5: Analysis
    print(f"[Step 5] Analyzing...")
    categories = classify_by_category(flattened)
    duplicates = detect_duplicates(flattened)
    pw_analysis = analyze_passwords(flattened)
    passkey_items = detect_passkeys(active_items)

    print(f"         Categories: {len(categories)}")
    print(f"         Duplicates: {len(duplicates)} group(s)")
    print(f"         Reused passwords: {len(pw_analysis['reused'])} group(s)")
    print(f"         Short passwords: {len(pw_analysis['short'])}")
    print(f"         Empty passwords: {len(pw_analysis['empty'])}")
    if passkey_items:
        print(f"         Passkeys: {len(passkey_items)} "
              f"(CANNOT be migrated — need manual re-enrollment)")

    # Step 6: Segregate and export
    counts, _, _ = segregate_and_export(
        flattened, out_dir, dry_run=args.dry_run, per_vault=args.per_vault)

    # Write passkeys checklist
    if passkey_items and not args.dry_run:
        pk_cols = ["Title", "URL", "Vault", "Action"]
        with open(out_dir / "passkeys_manual.csv", 'w', newline='',
                  encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=pk_cols)
            writer.writeheader()
            for pk in passkey_items:
                writer.writerow({
                    "Title": pk["title"],
                    "URL": pk["url"],
                    "Vault": pk["vault"],
                    "Action": "Re-enroll passkey in Apple Passwords",
                })
        print(f"[Step 6] passkeys_manual.csv          — "
              f"{len(passkey_items)} item(s) (re-enrollment checklist)")
    counts["passkeys"] = len(passkey_items)

    # Generate and write report (always written, even in dry run)
    report_text = generate_report(
        pux_path, vault_summary, state_counts, counts,
        categories, duplicates, pw_analysis, args.per_vault,
        attachment_count, passkey_items)

    with open(out_dir / "report.txt", 'w', encoding='utf-8') as f:
        f.write(report_text)

    # Print report to console
    print(f"\n{report_text}")

    print(f"\nAll files in: {out_dir}/")
    if not args.dry_run:
        print(f"Import: {out_dir}/apple_passwords_import.csv")
        print(f"\nTo securely delete output after import:")
        print(f"  python3 onepass_to_apple.py {pux_path} "
              f"-o {out_dir} --secure-delete")
    print()


if __name__ == "__main__":
    main()
