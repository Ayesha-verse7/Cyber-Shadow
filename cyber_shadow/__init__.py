"""
Cyber Shadow
============

An educational Password Policy Auditor & Dictionary Cracker Demo.

This package contains the core modules used by the Cyber Shadow
command-line application:

    policy   - Password policy / strength validation
    hashing  - MD5 / SHA-1 hash generation using hashlib
    storage  - JSON based local storage of generated test hashes
    cracker  - Educational dictionary attack against LOCAL test hashes only

IMPORTANT (Educational Use Only):
This tool is designed strictly for learning how password hashing and
dictionary attacks work. It only ever operates on hashes that YOU
generate yourself and store locally. It does not accept, import, or
attempt to crack hashes obtained from any external or real-world
source, and must never be used against systems or data you do not
own or have explicit permission to test.
"""

__version__ = "1.0.0"
__all__ = ["policy", "hashing", "storage", "cracker"]
