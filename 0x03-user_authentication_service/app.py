#!/usr/bin/env python3
""" Module for main app """

from flask import Flask, jsonify, request
from auth import Auth


AUTH = Auth()

app = Flask(__name__)


@app.route('/', methods=['GET'])
def greet() -> str:
    """ returns json message """
    return jsonify({"message": "Bienvenue"}), 200


@app.route('/users', methods=['POST'])
def register() -> str:
    """registers a new user"""
    email = request.form.get('email')
    password = request.form.get('password')
    try:
        user = AUTH.register_user(email, password)
        return jsonify({"email": user.email, "message": "user created"}), 200
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
