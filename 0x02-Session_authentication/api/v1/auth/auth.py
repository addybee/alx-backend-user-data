#!/usr/bin/env python3
"""
    API Authentication manager module
"""
from flask import request
from typing import List, TypeVar
import re
from os import getenv


class Auth:
    """
    Authentication Class Manager

    Check if authentication is required for the given path.

    Args:
        path (str): The path to check for authentication requirement.
        excluded_paths (List[str]): List of paths excluded
                                    from authentication.

    Returns:
        bool: True if authentication is required, False if not.

    Return the Authorization header value from the request.

    Args:
        request: The request object containing headers.

    Returns:
        str: Value of the Authorization header, or None if not present.

    gets the current logged in user

    Return:
    - the current user
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ Check if authentication is required for the given path.

        Args:
            path (str): The path to check for authentication requirement.
            excluded_paths (List[str]): List of paths excluded
                                        from authentication.

        Returns:
            bool: True if authentication is required, False if not.
        """
        if path is None or excluded_paths is None:
            return True
        if not path.endswith('/'):
            path += '/'
        for excluded_path in excluded_paths:
            if excluded_path.endswith('*'):
                if re.match(re.escape(excluded_path[:-1]), path):
                    return False
            elif excluded_path == path:
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """Return the Authorization header value from the request.

        Args:
            request: The request object containing headers.

        Returns:
            str: Value of the Authorization header, or None if not present.
        """
        if request is None:
            return None
        return request.headers.get('Authorization', None)

    def current_user(self, request=None) -> TypeVar('User'):
        """ gets the current logged in user
            Return:
            - the current user
        """
        return None

    def session_cookie(self, request=None):
        """returns a cookie value from a request"""
        if request is None:
            return None
        return request.cookies.get(getenv('SESSION_NAME'))
