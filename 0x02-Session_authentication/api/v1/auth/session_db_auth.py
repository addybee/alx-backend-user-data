#!/usr/bin/env python3
"""
    API Session DB Authentication manager module
"""
from datetime import datetime, timedelta
from api.v1.auth.session_exp_auth import SessionExpAuth
from models.user_session import UserSession


class SessionDBAuth(SessionExpAuth):
    """
    Session DB Authentication class
    """
    def __init__(self) -> None:
        super().__init__()
        UserSession.load_from_file()

    def create_session(self, user_id: str = None) -> str:
        """
        creates a Session ID for a user_id
        """
        session_id = super().create_session(user_id)
        user_session = UserSession(user_id=user_id, session_id=session_id)
        user_session.save()
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        Returns a User ID based on a Session ID.
        """

        if session_id is None or not isinstance(session_id, str):
            return None

        try:
            # Search for the session
            user_sessions = UserSession.search({'session_id': session_id})
            if not user_sessions:
                return None

            # If session duration is non-positive, return user ID immediately
            if self.session_duration <= 0:
                return user_sessions[0].user_id

            # Get the session's creation time
            created_at = user_sessions[0].created_at
            if not created_at:
                return None

            # Check if the session has expired
            if (created_at + timedelta(seconds=self.session_duration)) < \
                    datetime.utcnow():
                user_sessions[0].remove()
                return None

            # Return the user ID
            return user_sessions[0].user_id

        except Exception:
            return None

    def destroy_session(self, request=None) -> bool:
        """
        deletes a user session / logout
        """
        if request is None:
            return False
        session_id = self.session_cookie(request)
        if not session_id:
            return False
        user_id = self.user_id_for_session_id(session_id)
        if not user_id:
            return False
        try:
            UserSession.search({'session_id': session_id})[0].remove()
            return True
        except Exception:
            return False
