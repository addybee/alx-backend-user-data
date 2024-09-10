#!/usr/bin/env python3
""" DB module """
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError
# from typing import TypeVar

from user import Base, User


class DB:
    """DB class
    """
    __keys = ['id', 'email', 'hashed_password', 'session_id', 'reset_token']

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db", echo=False)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """add a user to DB"""
        user = User(email=email, hashed_password=hashed_password)
        if self.__session is None:
            self._session
        self.__session.add(user)
        self.__session.commit()
        return user

    def find_user_by(self, **kwargs: dict) -> User:
        """ finds a user base on the given parameters """
        if self.__session is None:
            self._session
        for key in kwargs.keys():
            if key not in self.__keys:
                raise InvalidRequestError
        query = self.__session.query(User).filter_by(**kwargs)
        user = query.first()
        if user is None:
            raise NoResultFound
        return user

    def update_user(self, user_id: int, **kwargs: dict) -> None:
        """ updates a user in DB """
        if self.__session is None:
            self._session
        user = self.find_user_by(id=user_id)
        for key, val in kwargs.items():
            if key not in self.__keys:
                raise ValueError
            setattr(user, key, val)
        self.__session.commit()
