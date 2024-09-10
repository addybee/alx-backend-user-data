#!/usr/bin/env python3
""" Module for Authentication """

from db import DB
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound
import bcrypt
import uuid

from user import User


def _hash_password(password: str) -> bytes:
    """ this function hashes a password """
    return bcrypt.hashpw(password.encode('utf8'), bcrypt.gensalt())


def _generate_uuid() -> str:
    """ generates a new uuid and returns it """
    return (str(uuid.uuid4()))


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self) -> None:
        """initilization of class instance"""
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """ register a new user """
        try:
            if self._db.find_user_by(email=email):
                raise ValueError(f"User {email} already exists")
        except NoResultFound:
            password = _hash_password(password).decode('utf8')
            return self._db.add_user(email, password)

    def valid_login(self, email: str, password: str) -> bool:
        """validates a user"""
        try:
            user = self._db.find_user_by(email=email)
            return bcrypt.checkpw(password.encode('utf-8'),
                                  user.hashed_password.encode('utf-8'))
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """generate a session id for a user"""
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id

        except Exception:
            return None
