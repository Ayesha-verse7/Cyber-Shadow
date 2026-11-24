"""
cyber_shadow.storage
======================

Hash Storage.

Saves and loads locally-generated, self-created test hashes to/from a
JSON file on disk. This is the ONLY source of hashes the cracker
module is ever allowed to operate on - there is no code path in this
project that imports or fetches a hash from anywhere external.

Each stored record looks like:

    {
        "label": "my_test_password_1",
        "algorithm": "sha1",
        "hash": "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3",
        "plaintext_length": 8
    }

Note: for a genuine educational demo, the plaintext is NOT stored -
only its length is kept for display purposes. The cracker has to
actually recompute hashes from the wordlist to find a match, exactly
like a real (simplified) dictionary attack would.
"""

from __future__ import annotations

import json
import os
from typing import List, Dict

DEFAULT_STORAGE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data",
    "test_hashes.json",
)


def _ensure_parent_dir(path: str) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)


def load_hashes(path: str = DEFAULT_STORAGE_PATH) -> List[Dict]:
    """
    Load the list of stored test-hash records from a JSON file.

    Returns an empty list if the file does not exist yet.

    Raises
    ------
    ValueError
        If the file exists but contains invalid/corrupt JSON.
    """
    if not os.path.exists(path):
        return []

    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return []
            data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Stored hash file is corrupted/invalid JSON: {exc}") from exc
    except OSError as exc:
        raise OSError(f"Could not read storage file '{path}': {exc}") from exc

    if not isinstance(data, list):
        raise ValueError("Stored hash file must contain a JSON array of records.")

    return data


def save_hashes(records: List[Dict], path: str = DEFAULT_STORAGE_PATH) -> None:
    """
    Overwrite the JSON storage file with the given list of records.

    Raises
    ------
    TypeError
        If records is not a list.
    OSError
        If the file cannot be written.
    """
    if not isinstance(records, list):
        raise TypeError("records must be a list of dictionaries.")

    _ensure_parent_dir(path)

    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(records, f, indent=4)
    except OSError as exc:
        raise OSError(f"Could not write storage file '{path}': {exc}") from exc


def add_hash_record(
    label: str,
    algorithm: str,
    digest: str,
    plaintext_length: int,
    path: str = DEFAULT_STORAGE_PATH,
) -> Dict:
    """
    Append a new test-hash record to storage and persist it.

    Returns the record that was added.
    """
    if not label or not isinstance(label, str):
        raise ValueError("label must be a non-empty string.")

    records = load_hashes(path)

    # Prevent duplicate labels so lookups stay unambiguous.
    existing_labels = {r.get("label") for r in records}
    original_label = label
    counter = 1
    while label in existing_labels:
        counter += 1
        label = f"{original_label}_{counter}"

    record = {
        "label": label,
        "algorithm": algorithm,
        "hash": digest,
        "plaintext_length": plaintext_length,
    }
    records.append(record)
    save_hashes(records, path)
    return record


def delete_hash_record(label: str, path: str = DEFAULT_STORAGE_PATH) -> bool:
    """
    Remove a record by its label. Returns True if a record was
    removed, False if no record with that label existed.
    """
    records = load_hashes(path)
    new_records = [r for r in records if r.get("label") != label]
    if len(new_records) == len(records):
        return False
    save_hashes(new_records, path)
    return True
