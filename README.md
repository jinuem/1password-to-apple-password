# 1Password to Apple Passwords Converter

A single offline Python script that converts 1Password `.1pux` exports into Apple Passwords-compatible CSV — with no data left behind.

## Why This Exists

Apple Passwords only accepts 6 fields: **Title, URL, Username, Password, Notes, OTPAuth**.

1Password stores much more — custom sections, multiple URLs, credit card details, software licenses, recovery codes, and other structured fields. A direct export loses all of that.

This script extracts everything, merges extra fields into the Notes column so nothing is lost, and separates items that need manual handling (like credit cards and software licenses).

## Security

- **100% offline** — no network calls, no APIs, no LLMs, no telemetry
- **No dependencies** — uses only Python standard library (`json`, `csv`, `zipfile`, `hashlib`, `argparse`)
- **Nothing leaves your machine** — input is read, output is written locally, temp files are cleaned up
- **Secure delete built in** — 3-pass overwrite (zeros → random → zeros) to wipe output files when done
- **Password analysis is local** — passwords are hashed with SHA-256 locally for duplicate detection, never transmitted

## Requirements

- Python 3.6+
- A `.1pux` export from 1Password

## How to Export from 1Password

1. Open **1Password desktop app**
2. Go to **File → Export** (or vault → Export)
3. Choose format: **1PUX**
4. Save the `.1pux` file
5. Run this script on that file

## Quick Start

```bash
python3 onepass_to_apple.py export.1pux
```

That's it. Output goes to `export_output/`. Import `apple_passwords_import.csv` into Apple Passwords.

## Usage

```
python3 onepass_to_apple.py <export.1pux> [options]

Options:
  -o, --output DIR       Output directory (default: <input_stem>_output)
  --dry-run              Preview report only — no password files written
  --per-vault            Generate one import CSV per vault
  --interactive          Choose which vaults to include/exclude
  --secure-delete        Overwrite output files with zeros and delete
```

### Examples

```bash
# Basic conversion
python3 onepass_to_apple.py export.1pux

# Custom output directory
python3 onepass_to_apple.py export.1pux -o ./my_output

# Preview what will happen without writing passwords
python3 onepass_to_apple.py export.1pux --dry-run

# Separate import file per vault
python3 onepass_to_apple.py export.1pux --per-vault

# Pick which vaults to include
python3 onepass_to_apple.py export.1pux --interactive

# Securely delete output files after importing
python3 onepass_to_apple.py export.1pux --secure-delete
```

## Output Files

```
export_output/
│
├── apple_passwords_import.csv    ← Import this into Apple Passwords
├── credit_cards.csv              ← Credit/debit cards (add to Apple Wallet)
├── software_licenses.csv         ← Software licenses (store elsewhere)
├── extra_fields_reference.csv    ← Items with custom fields before merge (backup)
├── extra_urls_only.csv           ← Items that only had extra URLs (reference)
├── otp_review.csv                ← Items with OTP in custom sections (reference)
├── all_fields_flat.csv           ← Full flat CSV with every column (archive)
├── raw_all_items.json            ← All items from all vaults as JSON
├── active_items.json             ← Active items only as JSON
├── report.txt                    ← Full report with analysis
│
├── files/                        ← Attachments from 1Password (license files, documents)
│   ├── license.pdf
│   └── ...
├── passkeys_manual.csv           ← Passkeys that need manual re-enrollment
│
└── per_vault/                    ← Only with --per-vault flag
    ├── apple_import_Private.csv
    ├── apple_import_Work.csv
    └── apple_import_Shared.csv
```

### What Goes Where

| Item Type | Destination | Action |
|-----------|-------------|--------|
| Standard logins | `apple_passwords_import.csv` | Import directly |
| Logins with custom fields | `apple_passwords_import.csv` | Extra fields merged into Notes |
| Logins with extra URLs | `apple_passwords_import.csv` | Extra URLs merged into Notes |
| Credit/debit cards | `credit_cards.csv` | Add to Apple Wallet manually |
| Software licenses | `software_licenses.csv` | Store in a notes app or spreadsheet |
| TOTP/2FA items | `apple_passwords_import.csv` | OTPAuth column preserved |
| File attachments (licenses, docs) | `files/` folder | Copied as-is from .1pux |
| Passkeys | `passkeys_manual.csv` | Cannot be migrated — re-enroll manually |

## Features

### File Attachments

1Password stores file attachments (license files, PDFs, documents, images) inside the `.1pux` export in a `files/` folder. Apple Passwords doesn't support attachments, so these files would normally be lost during migration.

The script automatically detects and copies all attachments from the `.1pux` to `export_output/files/`, preserving them exactly as they were stored in 1Password. The attachment count is included in `report.txt`.

### Passkey Detection

Passkeys (FIDO2/WebAuthn credentials) are cryptographic key pairs that **cannot be exported or transferred** between password managers. There is no standard format for passkey migration.

The script detects all passkey items and writes `passkeys_manual.csv` — a checklist with the site name, URL, and vault. For each entry:

1. Log into the site using your existing password (which *is* migrated)
2. Go to the site's security settings
3. Delete the old passkey (stored in 1Password)
4. Create a new passkey (stored in Apple Passwords / iCloud Keychain)

### Category-Aware Classification

Items are classified using 1Password's internal category IDs — not just field-name guessing. This correctly identifies:

| Category | ID | Handling |
|----------|----|----------|
| Login | 001 | Imported to Apple Passwords |
| Credit Card | 002 | Separated to `credit_cards.csv` |
| Secure Note | 003 | Imported (Notes field) |
| Identity | 004 | Imported with fields in Notes |
| Software License | 005 | Separated to `software_licenses.csv` |
| Bank Account | 006 | Imported with fields in Notes |
| Membership | 103 | Imported with fields in Notes |
| All others | * | Imported with fields in Notes |

If the category ID is missing, the script falls back to field-name heuristics (e.g., detecting "cardholder name" + "expiry date" as a credit card).

### Duplicate Detection

Finds items with the same URL domain + username across vaults. Common when items are copied between Personal and Work vaults. Duplicates are listed in `report.txt` — the script does not auto-remove them, so you can decide which to keep.

### Password Health Check

Runs entirely offline using SHA-256 hashing for comparison:

- **Empty passwords** — items with no password set
- **Short passwords** — fewer than 8 characters
- **Reused passwords** — same password used across multiple sites

All results appear in `report.txt`. Passwords are never logged or written in plaintext outside the CSV files.

### Notes Merging

For items with custom section fields or extra URLs, all data is appended to the Notes column:

```
Your existing notes here

--- 1Password Custom Fields ---
Recovery Codes: abc-123-def-456
Security Question: Name of first pet

--- Additional URLs ---
https://example.com/login
https://example.com/account
```

### Dry Run Mode

Preview the full report — vault breakdown, duplicates, password health, category counts — without writing any password-containing files:

```bash
python3 onepass_to_apple.py export.1pux --dry-run
```

Only `report.txt` is written. No CSVs or JSONs with sensitive data are created.

### Per-Vault Output

Generate separate Apple-compatible import files for each vault:

```bash
python3 onepass_to_apple.py export.1pux --per-vault
```

Useful if you want to import vaults into different Apple Passwords groups or devices selectively.

### Interactive Mode

Choose which vaults to include before processing:

```bash
python3 onepass_to_apple.py export.1pux --interactive
```

```
--- Vault Selection ---
  [1] Keyan / Private (312 items)
  [2] Keyan / Work (145 items)
  [3] Keyan / Shared (45 items)
  [A] All vaults

Enter vault numbers to include (comma-separated, or A for all): 1,2
```

### Secure Delete

After you've imported everything and verified it works, securely wipe the output:

```bash
python3 onepass_to_apple.py export.1pux --secure-delete
```

This performs a 3-pass overwrite on every file in the output directory:
1. Overwrite with zeros
2. Overwrite with random data
3. Overwrite with zeros again
4. Delete the files and directory

You'll be asked to type `YES` to confirm.

> **Note:** On SSDs with wear-leveling, secure deletion is not guaranteed at the hardware level. For maximum security, use FileVault (macOS full-disk encryption) and empty your Trash after deleting the output folder.

## How to Import into Apple Passwords

### macOS (Sequoia 15.0+)
1. Open **Passwords** app (or System Settings → Passwords)
2. Go to **File → Import Passwords**
3. Select `apple_passwords_import.csv`

### iOS / iPadOS
Import on Mac first — passwords sync via iCloud Keychain.

### Safari (older macOS)
1. Open **Safari → Settings → Passwords**
2. Click the **...** menu → **Import Passwords**
3. Select the CSV file

## How It Works

The script runs 6 steps in sequence:

1. **Extract** — Unzips the `.1pux` file, reads `export.data` (the JSON inside), and copies any attachments from the `files/` folder
2. **Collect** — Walks all accounts and vaults, pulls every item into a flat list
3. **Filter** — Keeps only active items (trashed/archived items are excluded)
4. **Flatten** — Converts nested JSON fields into flat CSV columns
5. **Analyze** — Detects duplicates, checks password health, classifies by category
6. **Segregate** — Classifies items, merges extra data into Notes, writes output files

## Multiple Vaults

The script handles multiple 1Password accounts and vaults automatically. All vaults are combined into a single import file by default. Use `--per-vault` for separate files, or `--interactive` to pick specific vaults.

The vault name is preserved in `all_fields_flat.csv` (column `_vault_name`) if you need to trace which item came from which vault.

## Troubleshooting

| Problem | Solution |
|---------|----------|
| "No export.data found" | Re-export from 1Password. The `.1pux` file may be corrupted. |
| "Not a valid zip/1pux file" | Ensure you exported as `.1pux`, not `.csv` or `.json`. |
| Items missing after import | Check `credit_cards.csv` and `software_licenses.csv` — those are intentionally excluded. Check `report.txt` for full counts. |
| Trashed items appearing | They shouldn't — the script filters to `state: active` only. Check `report.txt` for the state breakdown. |
| Duplicates in Apple Passwords | Check the duplicates section in `report.txt`. Remove duplicates from the CSV before importing, or de-duplicate in Apple Passwords after. |
| OTP not working | Check `otp_review.csv`. If OTPAuth column is empty for an item, the TOTP secret is in Notes as text — you'll need to re-add it manually in Apple Passwords. |

## License

MIT — Use freely, modify as needed, no warranty.

## Disclaimer

This tool is not affiliated with 1Password or Apple. Always verify your import by spot-checking a few entries in Apple Passwords after importing. Keep your `.1pux` file as a backup until you've confirmed everything imported correctly.
