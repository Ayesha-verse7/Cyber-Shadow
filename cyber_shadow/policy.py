"""
cyber_shadow.policy
====================

Password Policy Checker.

Validates a password against a configurable policy:
    - Minimum length
    - Requires at least one uppercase letter
    - Requires at least one lowercase letter
    - Requires at least one digit
    - Requires at least one special character

Also provides a simple strength score / rating so the user gets
beginner-friendly, actionable feedback.
"""

from __future__ import annotations

import re
import string
from dataclasses import dataclass, field


# Default policy settings. These can be overridden when calling
# check_password_policy() by passing different keyword arguments.
DEFAULT_MIN_LENGTH = 8
SPECIAL_CHARACTERS = string.punctuation  # e.g. !"#$%&'()*+,-./:;<=>?@[\]^_`{|}~


@dataclass
class PolicyResult:
    """Holds the outcome of a password policy check."""

    password_length: int
    min_length: int
    has_upper: bool
    has_lower: bool
    has_digit: bool
    has_special: bool
    failures: list = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        """True only if every policy rule passed."""
        return len(self.failures) == 0

    @property
    def score(self) -> int:
        """
        A simple 0-5 strength score based on how many individual
        checks passed (length, upper, lower, digit, special).
        """
        checks = [
            self.password_length >= self.min_length,
            self.has_upper,
            self.has_lower,
            self.has_digit,
            self.has_special,
        ]
        return sum(1 for c in checks if c)

    @property
    def rating(self) -> str:
        """Human-friendly strength label derived from the score."""
        ratings = {
            0: "Very Weak",
            1: "Very Weak",
            2: "Weak",
            3: "Moderate",
            4: "Strong",
            5: "Very Strong",
        }
        return ratings.get(self.score, "Unknown")


def check_password_policy(
    password: str,
    min_length: int = DEFAULT_MIN_LENGTH,
    require_upper: bool = True,
    require_lower: bool = True,
    require_digit: bool = True,
    require_special: bool = True,
) -> PolicyResult:
    """
    Validate a password string against the password policy.

    Parameters
    ----------
    password : str
        The password to validate. Must be a non-empty string.
    min_length : int
        Minimum number of characters required.
    require_upper, require_lower, require_digit, require_special : bool
        Toggle individual rule enforcement.

    Returns
    -------
    PolicyResult
        A dataclass describing exactly which checks passed/failed.

    Raises
    ------
    TypeError
        If `password` is not a string.
    """
    if not isinstance(password, str):
        raise TypeError("Password must be provided as a string.")

    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = any(ch in SPECIAL_CHARACTERS for ch in password)

    result = PolicyResult(
        password_length=len(password),
        min_length=min_length,
        has_upper=has_upper,
        has_lower=has_lower,
        has_digit=has_digit,
        has_special=has_special,
    )

    failures = []
    if len(password) < min_length:
        failures.append(
            f"Password must be at least {min_length} characters long "
            f"(currently {len(password)})."
        )
    if require_upper and not has_upper:
        failures.append("Password must contain at least one uppercase letter (A-Z).")
    if require_lower and not has_lower:
        failures.append("Password must contain at least one lowercase letter (a-z).")
    if require_digit and not has_digit:
        failures.append("Password must contain at least one digit (0-9).")
    if require_special and not has_special:
        failures.append(
            "Password must contain at least one special character "
            f"(e.g. {SPECIAL_CHARACTERS[:10]}...)."
        )

    result.failures = failures
    return result


def format_policy_report(result: PolicyResult) -> str:
    """Build a readable, beginner-friendly multi-line report string."""
    lines = []
    lines.append("Password Policy Report")
    lines.append("-" * 40)
    lines.append(f"Length            : {result.password_length} "
                  f"(minimum required: {result.min_length})")
    lines.append(f"Has uppercase     : {'Yes' if result.has_upper else 'No'}")
    lines.append(f"Has lowercase     : {'Yes' if result.has_lower else 'No'}")
    lines.append(f"Has digit         : {'Yes' if result.has_digit else 'No'}")
    lines.append(f"Has special char  : {'Yes' if result.has_special else 'No'}")
    lines.append(f"Strength score    : {result.score}/5 ({result.rating})")
    lines.append("-" * 40)

    if result.is_valid:
        lines.append("Result: PASS - This password meets the policy requirements.")
    else:
        lines.append("Result: FAIL - This password does not meet the policy:")
        for i, reason in enumerate(result.failures, start=1):
            lines.append(f"  {i}. {reason}")

    return "\n".join(lines)
