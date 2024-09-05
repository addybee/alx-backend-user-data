#!/usr/bin/env python3
"""Module of Session Login and Logout"""
from api.v1.views import app_views
from flask import request, jsonify, make_response, abort
from models.user import User


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login() -> str:
    """handles session authentication login"""
    from api.v1.app import auth
    from os import getenv

    email, password = (request.form.get('email', None),
                       request.form.get('password', None))
    if not email:
        return jsonify({"error": "email missing"}), 400
    if not password:
        return jsonify({"error": "password missing"}), 400
    try:
        users = User.search({'email': email})
        if not users:
            return jsonify({"error": "no user found for this email"}), 404
        if not users[0].is_valid_password(password):
            return jsonify({"error": "wrong password"}), 401

        sesion_id = auth.create_session(users[0].id)
        response = make_response(jsonify(users[0].to_json()))
        response.set_cookie(getenv('SESSION_NAME'), sesion_id)
        return response
    except Exception as e:
        return jsonify({"error": "no user found for this email"}), 404


@app_views.route('/auth_session/logout', methods=['DELETE'],
                 strict_slashes=False)
def logout() -> str:
    """deletes a session and logout a user"""
    from api.v1.app import auth

    if not auth.destroy_session(request):
        abort(404)
    return jsonify({}), 200
