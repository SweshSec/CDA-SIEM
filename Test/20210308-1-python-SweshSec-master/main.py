#!/usr/bin/env python3

from flask import Flask, request, make_response, jsonify, g
from flask_httpauth import HTTPBasicAuth, HTTPTokenAuth
from functools import wraps
import logging
import hashlib
import os
import jwt

app = Flask(__name__)

env = os.environ["APP_ENV"]
with open('./data/keys/' + env) as f:
    app.config['JWT_SECRET_KEY'] = f.read().rstrip()

basic_auth = HTTPBasicAuth()
bearer_auth = HTTPTokenAuth('Bearer')


@basic_auth.verify_password
def verify_password(username, password):
    with open('./data/auth/' + username, 'r') as f:
        file_contents = f.read().rstrip()
        if len(file_contents) != 128:
            g.auth_err = "File not a user hash file: %s" % file_contents
            return False

        pwhash = hashlib.sha512(password.encode('utf-8')).hexdigest()

        if pwhash != file_contents:
            g.auth_err = "Credentials %s / %s are invalid" % (
                username, password)
            return False
        else:
            return True


@basic_auth.error_handler
def basic_auth_error():
    logging.warning(g.auth_err)
    return make_response(jsonify({"error": g.auth_err}), 401)


@bearer_auth.verify_token
def verify_token(token):
    try:
        if jwt.get_unverified_header(token).get('kid', None) == "debugKey":
            res = jwt.decode(token, verify=False)
        else:
            res = jwt.decode(
                token, app.config['JWT_SECRET_KEY'], algorithms=["HS256"])
    except Exception as e:
        g.auth_err = str(e)
        return False

    if res:
        g.user = res['id']

    return res


@bearer_auth.error_handler
def bearer_auth_error():
    logging.warn(g.auth_err)
    return make_response(jsonify({'error': g.auth_err}))


@app.after_request
def add_response_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'

    if hasattr(g, 'user'):
        response.headers['X-Username'] = g.user

    return response


def get_username(func):
    @wraps(func)
    def wrap(*args, **kwargs):
        if 'X-Username' in request.headers:
            g.user = request.headers['X-Username']

        return func(*args, **kwargs)

    return wrap


@app.route('/auth/v1/token', methods=["POST"])
@basic_auth.login_required
def get_token():
    auth_method = request.form["method"]

    if auth_method != "basic":
        return make_response(jsonify({"error": "Invalid method"}), 401)

    token = jwt.encode({"id": basic_auth.username()},
                       app.config['JWT_SECRET_KEY'], algorithm='HS256')

    return jsonify({"token": token.decode('utf-8')})


@app.route('/protected/v1/important')
@bearer_auth.login_required
@get_username
def get_important():
    if g.user == "admin":
        return jsonify({"adminCode": 29485039563027385})
    else:
        return jsonify({"userCode": 384573753734376})


if __name__ == "__main__":
    logging.basicConfig(format='%(asctime)s %(message)s', level=logging.DEBUG)
    app.run(host="0.0.0.0", port=1337, debug=False)
