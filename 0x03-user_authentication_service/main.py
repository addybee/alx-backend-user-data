#!/usr/bin/env python3
"""
Main file
"""
import requests


def register_user(email: str, password: str) -> None:
    """test register endpoint"""
    url = 'http://127.0.0.1:5000/users'
    data = {
        'email': email,
        'password': password
    }
    response = requests.post(url, data=data)
    expected_output = {"email": email, "message": "user created"}
    assert response.status_code == 200
    assert response.json() == expected_output


def log_in_wrong_password(email: str, password: str) -> None:
    """test the login route with wrong password"""
    url = 'http://127.0.0.1:5000/sessions'
    data = {
        'email': email,
        'password': password
    }
    response = requests.post(url, data=data)
    expected_output = {"email": email, "message": "logged in"}
    assert response.status_code == 401


def log_in(email: str, password: str) -> str:
    """test the login route with correct password"""
    url = 'http://127.0.0.1:5000/sessions'
    data = {
        'email': email,
        'password': password
    }
    response = requests.post(url, data=data)
    expected_output = {"email": email, "message": "logged in"}
    assert response.status_code == 200
    assert response.json() == expected_output
    return response.cookies.get('session_id')


def profile_unlogged() -> None:
    """ gets an unlogged user profile """
    url = 'http://127.0.0.1:5000/profile'
    response = requests.get(url)
    assert response.status_code == 403


def profile_logged(session_id: str) -> None:
    """gets a logged user profile"""
    url = 'http://127.0.0.1:5000/profile'
    cookies = {'session_id': session_id}
    response = requests.get(url, cookies=cookies)
    assert response.status_code == 200


def log_out(session_id: str) -> None:
    """test logout route"""
    url = 'http://127.0.0.1:5000/sessions'
    cookies = {'session_id': session_id}

    response = requests.delete(url, cookies=cookies)
    assert response.status_code == 200


def reset_password_token(email: str) -> str:
    """test reset password route"""
    url = 'http://127.0.0.1:5000/reset_password'
    data = {'email': email}
    response = requests.post(url, data=data)
    assert response.status_code == 200
    return response.json().get('reset_token')


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """test the update password route"""
    url = 'http://127.0.0.1:5000/reset_password'
    data = {'email': email,
            'new_password': new_password,
            'reset_token': reset_token
            }
    response = requests.put(url, data=data)
    assert response.status_code == 200
    assert response.json() == {"email": email, "message": "Password updated"}


EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"


if __name__ == "__main__":

    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
