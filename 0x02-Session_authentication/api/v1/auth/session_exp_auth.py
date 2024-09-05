#!/usr/bin/env python3
"""Module of Session Expiration Authentication"""
from datetime import datetime, timedelta
from api.v1.auth.session_auth import SessionAuth
import os


class SessionExpAuth(SessionAuth):
    """class of Session Expiration Authentication"""
    def __init__(self) -> None:
        super().__init__()
        try:
            self.session_duration = int(os.getenv('SESSION_DURATION'))
        except Exception:
            self.session_duration = 0

    def create_session(self, user_id: str = None) -> str:
        """creates a Session ID for a user_id"""
        session_id = super().create_session(user_id)
        if not session_id:
            return None
        self.user_id_by_session_id[session_id] = {
            'user_id': user_id,
            'created_at': datetime.now()
        }
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """returns a User ID based on a Session ID"""
        if session_id is None or not isinstance(session_id, str):
            return None
        if session_id not in self.user_id_by_session_id.keys():
            return None
        if self.session_duration <= 0:
            return self.user_id_by_session_id.get(session_id).get('user_id')
        created_at = self.user_id_by_session_id.get(session_id
                                                    ).get('created_at', None)
        if not created_at:
            return None
        if (created_at + timedelta(seconds=self.session_duration)) < datetime.\
                now():
            return None
        return self.user_id_by_session_id.get(session_id).get('user_id')
