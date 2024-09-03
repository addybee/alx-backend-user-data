#!/usr/bin/env python3
"""
    API Authentication manager module
"""
from flask import request
from typing import List, TypeVar


class Auth:
    """
        Authentication Class Manager
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
        if path in excluded_paths:
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
        auth_key = request.headers.get('Authorization', None)
        if auth_key:
            return auth_key
        return auth_key

    def current_user(self, request=None) -> TypeVar('User'):
        """ gets the current logged in user"""
        return None


class BasicAuth(Auth):
    """Basic Authentication class"""
    pass
