# Cyber Shadow

**Password Policy Auditor & Educational Cracker Demo**

A beginner-friendly, menu-driven command-line tool for learning how
password policies, hashing (MD5/SHA-1), and simple dictionary attacks
work — built entirely with the Python standard library.

> **Educational use only.** The dictionary cracker only ever operates
> on hashes that *you* generate and save yourself via this tool, and
> it only searches a local wordlist file (`data/test_wordlist.txt`).
> It performs no network access and does not store any real-world or
> third-party password hashes. Do not use this tool, or any part of
> it, against systems, accounts, or data you do not own or have
> explicit permission to test.

## Project Structure

```
Cyber-Shadow/
├── main.py                       # CLI entry point / main menu loop
├── cyber_shadow/
│   ├── __init__.py               # Package metadata
│   ├── policy.py                 # Password Policy Checker
│   ├── hashing.py                # MD5 / SHA-1 Hash Generator
│   ├── storage.py                # JSON storage for self-generated test hashes
│   └── cracker.py                # Educational dictionary cracker
├── data/
│   ├── test_wordlist.txt         # Local wordlist used by the cracker
│   └── test_hashes.json          # Created automatically when you save a hash
├── requirements.txt               # No third-party deps (stdlib only)
└── README.md
```

## Requirements

- Python 3.10+ (developed/tested against Python 3.12; written to be
  fully compatible with Python 3.14.10 as requested — no syntax or
  stdlib features beyond 3.10 are used).
- No third-party packages. `requirements.txt` is included for
  convention but installs nothing.

## How to Run

From the `Cyber-Shadow/` project root:

```bash
python main.py
```

(or `python3 main.py` / `py main.py`, depending on your system's
Python launcher.)

## Features / Main Menu

```
1. Check password against security policy
2. Generate MD5 / SHA-1 hash of a password
3. Save a new self-generated test hash
4. Run educational dictionary cracker (local test hash)
5. View last cracking performance statistics
0. Exit
```

### 1. Password Policy Checker
Validates a password against:
- Minimum length (default: 8 characters)
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character

Returns a 0–5 strength score and a readable pass/fail report listing
exactly which rules failed.

### 2. Hash Generator
Generates genuine **MD5** and **SHA-1** hex digests of a password
using Python's built-in `hashlib`. Includes a short note on why these
fast, unsalted algorithms are unsuitable for real-world password
storage.

### 3. Hash Storage
Saves a label + algorithm + hash (and plaintext length only — never
the plaintext itself) to `data/test_hashes.json`. Duplicate labels
are automatically de-duplicated.

### 4. Educational Dictionary Cracker
Lets you pick one of your saved test hashes, then hashes every word
in `data/test_wordlist.txt` (or a custom local wordlist you point it
at) with the matching algorithm, comparing digests until a match is
found or the list is exhausted.

### 5. Performance Statistics
Reports the number of attempts made, total wordlist size, elapsed
wall-clock time, and computed attempts-per-second for the most recent
cracking run in the current session.

## Example Session

```
Select an option (0-5): 2
Enter a password to hash: password

  Plaintext length : 8 characters
  MD5  : 5f4dcc3b5aa765d61d8327deb882cf99
  SHA1 : 5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8
```

```
Select an option (0-5): 4
  Available saved test hashes:
    1. [SHA1] dragon_record -> af8978b1797b72acfff9595a5a2a373ec3d9106d
  Select a hash by number (1-1): 1
  Press Enter to use the default local wordlist...

Dictionary Attack Report
----------------------------------------
Algorithm         : SHA1
Wordlist size     : 50 candidate(s)
Attempts made     : 11
Elapsed time      : 0.000009 seconds
Attempts / second : 1,280,111.72
Result            : MATCH FOUND -> 'dragon'
----------------------------------------
```

## Testing Performed

This project was built and verified end-to-end before delivery:
- All modules import cleanly with correct relative paths.
- `hashlib`-based MD5/SHA-1 output verified against known reference
  digests (e.g. MD5 of `"password"` =
  `5f4dcc3b5aa765d61d8327deb882cf99`).
- Policy checker tested against both a weak and a strong password.
- Storage save/load round-trip tested.
- Cracker tested for **both** a successful match (word present in the
  wordlist) and an unsuccessful match (word absent — the cracker
  correctly exhausts the full wordlist and reports "no match").
- Full interactive menu loop tested end-to-end via scripted input,
  exercising every option (1–5) plus Exit, with a clean (0) exit
  code.
- Edge cases checked: invalid menu selections, empty input retries,
  no saved hashes yet, and graceful shutdown on exhausted/interrupted
  input (no infinite loops).
- All files pass `python -m py_compile` with no syntax errors.

## Notes

- `data/test_hashes.json` is created automatically the first time you
  save a hash (option 3) — it does not need to exist beforehand.
- Only the hash and plaintext length are ever stored, never the
  plaintext password.
- Feel free to edit `data/test_wordlist.txt` to add your own test
  words for experimentation.
