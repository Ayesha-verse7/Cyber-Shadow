#!/usr/bin/env python3
"""
Cyber Shadow - Password Policy Auditor & Educational Cracker Demo
====================================================================

A beginner-friendly, menu-driven command-line application that lets
you:

    1. Check a password against a configurable security policy.
    2. Generate genuine MD5 / SHA-1 hashes of a password.
    3. Save a self-generated hash to local JSON storage as test data.
    4. Run an educational dictionary attack against one of your own
       locally-stored test hashes, using a local wordlist.
    5. View performance statistics (attempts & elapsed time) from the
       most recent cracking attempt.

EDUCATIONAL USE ONLY:
    Every hash this tool ever tries to "crack" is one that YOU
    generated and saved yourself, from a password YOU typed in.
    The dictionary attack only ever runs against the local
    data/test_wordlist.txt file (or another local file you choose).
    This project does not, and must not, be used to attack real
    accounts, systems, or any hash you do not own.

Run with:
    python main.py
"""

from __future__ import annotations

import os
import sys

# Make sure the project root is on sys.path so `import cyber_shadow`
# works no matter what directory this script is launched from.
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from cyber_shadow import policy, hashing, storage, cracker  # noqa: E402


# ---------------------------------------------------------------------------
# Helper / input utilities
# ---------------------------------------------------------------------------

def print_header(title: str) -> None:
    print()
    print("=" * 60)
    print(title.center(60))
    print("=" * 60)


def print_main_menu() -> None:
    print_header("CYBER SHADOW - Password Security Toolkit")
    print(" 1. Check password against security policy")
    print(" 2. Generate MD5 / SHA-1 hash of a password")
    print(" 3. Save a new self-generated test hash")
    print(" 4. Run educational dictionary cracker (local test hash)")
    print(" 5. View last cracking performance statistics")
    print(" 0. Exit")
    print("-" * 60)


def prompt_nonempty(prompt_text: str) -> str:
    """Keep asking until the user provides a non-empty string."""
    while True:
        try:
            value = input(prompt_text)
        except EOFError:
            # No more input available (e.g. piped/redirected stdin ran out,
            # or Ctrl-D was pressed). Treat this the same as a user exit
            # request instead of looping forever.
            raise KeyboardInterrupt("No more input available.")
        if value.strip() != "":
            return value
        print("  [!] Input cannot be empty. Please try again.")


def prompt_choice(prompt_text: str, valid_choices) -> str:
    """Keep asking until the user picks one of the valid choices."""
    valid_set = {str(c).lower() for c in valid_choices}
    while True:
        try:
            value = input(prompt_text).strip().lower()
        except EOFError:
            raise KeyboardInterrupt("No more input available.")
        if value in valid_set:
            return value
        print(f"  [!] Invalid choice. Please enter one of: "
              f"{', '.join(str(c) for c in valid_choices)}")


def prompt_algorithm() -> str:
    return prompt_choice(
        "  Choose algorithm [md5/sha1]: ", ["md5", "sha1"]
    )


# ---------------------------------------------------------------------------
# Menu option 1: Password Policy Checker
# ---------------------------------------------------------------------------

def menu_check_policy() -> None:
    print_header("Password Policy Checker")
    try:
        password = prompt_nonempty("Enter a password to check: ")
        result = policy.check_password_policy(password)
        print()
        print(policy.format_policy_report(result))
    except TypeError as exc:
        print(f"[ERROR] {exc}")
    except Exception as exc:  # defensive catch-all for a CLI tool
        print(f"[UNEXPECTED ERROR] {exc}")


# ---------------------------------------------------------------------------
# Menu option 2: Hash Generator
# ---------------------------------------------------------------------------

def menu_generate_hash() -> None:
    print_header("Hash Generator (MD5 / SHA-1)")
    try:
        password = prompt_nonempty("Enter a password to hash: ")
        hashes = hashing.generate_all_hashes(password)
        print()
        print(f"  Plaintext length : {len(password)} characters")
        print(f"  MD5  : {hashes['md5']}")
        print(f"  SHA1 : {hashes['sha1']}")
        print()
        print("  Note: MD5 and SHA-1 are fast, unsalted hashes - fine for")
        print("  this learning demo, but NOT safe for real password storage.")
    except TypeError as exc:
        print(f"[ERROR] {exc}")
    except Exception as exc:
        print(f"[UNEXPECTED ERROR] {exc}")


# ---------------------------------------------------------------------------
# Menu option 3: Save a self-generated test hash
# ---------------------------------------------------------------------------

def menu_save_test_hash() -> None:
    print_header("Save a New Self-Generated Test Hash")
    try:
        password = prompt_nonempty(
            "Enter a password to hash and save as local test data: "
        )
        algo = prompt_algorithm()
        digest = hashing.generate_hash(password, algo)

        label = input(
            "Enter a label for this test hash (press Enter for auto-label): "
        ).strip()
        if not label:
            existing = storage.load_hashes()
            label = f"test_hash_{len(existing) + 1}"

        record = storage.add_hash_record(
            label=label,
            algorithm=algo,
            digest=digest,
            plaintext_length=len(password),
        )
        print()
        print("  Saved successfully:")
        print(f"    Label     : {record['label']}")
        print(f"    Algorithm : {record['algorithm'].upper()}")
        print(f"    Hash      : {record['hash']}")
        print(f"    Stored at : {storage.DEFAULT_STORAGE_PATH}")
        print()
        print("  Reminder: the plaintext password itself is NOT stored -")
        print("  only its hash and length are kept.")
    except (TypeError, ValueError) as exc:
        print(f"[ERROR] {exc}")
    except OSError as exc:
        print(f"[FILE ERROR] {exc}")
    except Exception as exc:
        print(f"[UNEXPECTED ERROR] {exc}")


# ---------------------------------------------------------------------------
# Menu option 4: Educational Dictionary Cracker
# ---------------------------------------------------------------------------

LAST_CRACK_RESULT = None  # populated after a successful run, used by option 5


def _choose_stored_hash():
    """Let the user pick one of their saved test-hash records."""
    records = storage.load_hashes()
    if not records:
        print("  [!] No saved test hashes found. Use option 3 first to "
              "create one.")
        return None

    print("\n  Available saved test hashes:")
    for i, rec in enumerate(records, start=1):
        print(f"    {i}. [{rec.get('algorithm', '?').upper()}] "
              f"{rec.get('label')} -> {rec.get('hash')}")

    valid_indices = [str(i) for i in range(1, len(records) + 1)]
    choice = prompt_choice(
        f"  Select a hash by number (1-{len(records)}): ", valid_indices
    )
    return records[int(choice) - 1]


def menu_run_cracker() -> None:
    global LAST_CRACK_RESULT
    print_header("Educational Dictionary Cracker")
    print("  This runs ONLY against your own local test hashes and the")
    print("  local wordlist in data/test_wordlist.txt.\n")

    try:
        record = _choose_stored_hash()
        if record is None:
            return

        target_hash = record["hash"]
        algorithm = record["algorithm"]

        wordlist_path = cracker.DEFAULT_WORDLIST_PATH
        custom = input(
            "  Press Enter to use the default local wordlist, or type a "
            "custom local wordlist path: "
        ).strip()
        if custom:
            wordlist_path = custom

        print("\n  Running dictionary attack... please wait.\n")
        result = cracker.crack_hash(
            target_hash=target_hash,
            algorithm=algorithm,
            wordlist_path=wordlist_path,
        )
        LAST_CRACK_RESULT = result

        print(cracker.format_crack_report(result))

    except FileNotFoundError as exc:
        print(f"[ERROR] {exc}")
    except (TypeError, ValueError) as exc:
        print(f"[ERROR] {exc}")
    except OSError as exc:
        print(f"[FILE ERROR] {exc}")
    except Exception as exc:
        print(f"[UNEXPECTED ERROR] {exc}")


# ---------------------------------------------------------------------------
# Menu option 5: Performance statistics from the last crack attempt
# ---------------------------------------------------------------------------

def menu_show_stats() -> None:
    print_header("Last Cracking Performance Statistics")
    if LAST_CRACK_RESULT is None:
        print("  No dictionary attack has been run yet in this session.")
        print("  Choose option 4 first.")
        return

    print(cracker.format_crack_report(LAST_CRACK_RESULT))


# ---------------------------------------------------------------------------
# Main application loop
# ---------------------------------------------------------------------------

MENU_ACTIONS = {
    "1": menu_check_policy,
    "2": menu_generate_hash,
    "3": menu_save_test_hash,
    "4": menu_run_cracker,
    "5": menu_show_stats,
}


def main() -> None:
    print("Welcome to Cyber Shadow - an educational password security toolkit.")
    print("All cracking features operate ONLY on local, self-generated test")
    print("data. Use this tool responsibly and only on data you own.")

    while True:
        try:
            print_main_menu()
            try:
                choice = input("Select an option (0-5): ").strip()
            except EOFError:
                raise KeyboardInterrupt("No more input available.")

            if choice == "0":
                print("\nExiting Cyber Shadow. Stay safe out there!")
                break

            action = MENU_ACTIONS.get(choice)
            if action is None:
                print("  [!] Invalid option. Please choose a number from 0 to 5.")
                continue

            action()

        except KeyboardInterrupt:
            print("\n\nInterrupted by user. Exiting Cyber Shadow.")
            break
        except Exception as exc:
            # Top-level safety net so an unexpected error never crashes
            # the whole menu loop.
            print(f"\n[UNEXPECTED ERROR] Something went wrong: {exc}")
            print("Returning to main menu...\n")


if __name__ == "__main__":
    main()
