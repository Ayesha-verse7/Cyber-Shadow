"""
cyber_shadow.hashing
=====================

Hash Generator.

Generates genuine MD5 and SHA-1 hashes of a given password using
Python's built-in `hashlib` module. These algorithms are intentionally
weak/fast and are used here ONLY to demonstrate, for educational
purposes, why they are unsuitable for securely storing real
passwords (no salting, very fast to brute-force).

This module never contacts the network and never reads data from
anywhere other than what the user types in, or what is loaded from
the local test-hash storage file.
"""

from __future__ import annotations

import hashlib

SUPPORTED_ALGORITHMS = ("md5", "sha1")


def generate_hash(password: str, algorithm: str = "sha1") -> str:
    """
    Generate a hex-digest hash of `password` using the requested
    algorithm.

    Parameters
    ----------
    password : str
        The plaintext string to hash.
    algorithm : str
        Either "md5" or "sha1" (case-insensitive).

    Returns
    -------
    str
        The lowercase hexadecimal digest.

    Raises
    ------
    TypeError
        If password is not a string.
    ValueError
        If the algorithm is not supported.
    """
    if not isinstance(password, str):
        raise TypeError("Password must be a string.")

    algo = algorithm.strip().lower()
    if algo not in SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm '{algorithm}'. "
            f"Supported algorithms: {', '.join(SUPPORTED_ALGORITHMS)}."
        )

    data = password.encode("utf-8")

    if algo == "md5":
        digest = hashlib.md5(data).hexdigest()
    else:  # sha1
        digest = hashlib.sha1(data).hexdigest()

    return digest


def generate_all_hashes(password: str) -> dict:
    """
    Convenience helper: generate both MD5 and SHA-1 hashes for a
    password in one call.

    Returns
    -------
    dict
        {"md5": "<hex digest>", "sha1": "<hex digest>"}
    """
    return {
        "md5": generate_hash(password, "md5"),
        "sha1": generate_hash(password, "sha1"),
    }


def verify_hash(password: str, expected_digest: str, algorithm: str = "sha1") -> bool:
    """
    Check whether hashing `password` with `algorithm` produces
    `expected_digest`. Used by the cracker module.
    """
    if not isinstance(expected_digest, str):
        raise TypeError("expected_digest must be a string.")
    return generate_hash(password, algorithm) == expected_digest.strip().lower()
