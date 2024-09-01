#!/usr/bin/env python3
"""
This module provides functions for securely hashing passwords and
verifying hashed passwords using the bcrypt library.
"""

import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hashes a plain-text password using bcrypt.

    Args:
        password (str): The plain-text password to be hashed.

    Returns:
        bytes: The hashed password in bytes format, including the salt.

    Example:
        >>> hashed = hash_password("my_secret_password")
        >>> print(hashed)
        b'$2b$12$KIXG9zq5DB0Jc3F.H1uj.eI4owG2V4FfJ/wJZh9isrF5lIVY8UBK6'
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Verifies that a plain-text password matches the hashed password.

    Args:
        hashed_password (bytes): The previously hashed password.
        password (str): The plain-text password to verify.

    Returns:
        bool: True if password matches the hashed password, False otherwise.

    Example:
        >>> hashed = hash_password("my_secret_password")
        >>> result = is_valid(hashed, "my_secret_password")
        >>> print(result)
        True
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
