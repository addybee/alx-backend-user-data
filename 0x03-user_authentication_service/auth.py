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

    def get_user_from_session_id(self, session_id: str) -> User:
        """ finds a user by session id"""
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except Exception:
            return None

    def destroy_session(self, user_id: int) -> None:
        """destroys a user current session"""
        if user_id is None:
            return None
        try:
            user = self._db.update_user(user_id, session_id=None)
        except Exception:
            return None

    def get_reset_password_token(self, email: str) -> str:
        """ generate a password reset token """
        if email is None:
            return None
        try:
            user = self._db.find_user_by(email=email)
            reset_token = _generate_uuid()
            self._db.update_user(user.id, reset_token=reset_token)
            return reset_token
        except Exception:
            raise ValueError

    def update_password(self, reset_token: str, password: str) -> None:
        """update a users password"""
        if reset_token is None or password is None:
            return None
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            password = _hash_password(password).decode('utf-8')
            self._db.update_user(user.id, reset_token=None,
                                 hashed_password=password)
        except Exception:
            raise ValueError
