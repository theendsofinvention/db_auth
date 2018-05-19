# coding=utf-8

import os
import uuid
from urllib.parse import urlencode

import requests
from flask import Flask, jsonify, make_response, request

from _config import DB_KEY, DB_SECRET, GH_KEY, GH_SECRET, HTML_TEMPLATE, REDIRECT_URI_TEMPLATE, STORE

app = Flask('db_auth')
app.secret_key = os.getenv('app_secret')

LOGIN_URL = {
    'github': r'https://github.com/login/oauth/authorize?',
    'dropbox': r'https://www.dropbox.com/1/oauth2/authorize?',
}

AUTHORIZED_URL = {
    'github': r'https://github.com/login/oauth/access_token',
    'dropbox': r'https://api.dropboxapi.com/1/oauth2/token',
}


def _get_login_url(app_name: str) -> str:
    return LOGIN_URL[app_name]


def _get_login_params(app_name: str, user_id: str):
    if app_name == 'dropbox':
        return {
            'client_id': DB_KEY,
            'response_type': 'code',
            'redirect_uri': REDIRECT_URI_TEMPLATE.format(app=app_name),
            'state': user_id,
        }
    elif app_name == 'github':
        return {
            'client_id': GH_KEY,
            'redirect_uri': REDIRECT_URI_TEMPLATE.format(app=app_name),
            'scope': 'repo',
            'state': user_id,
        }


def _get_authorized_params(app_name: str, user_id: str, code: str):
    if app_name == 'github':
        return {
            'client_id': GH_KEY,
            'client_secret': GH_SECRET,
            'code': code,
            'redirect_uri': REDIRECT_URI_TEMPLATE.format(app=app_name),
            'state': user_id,
        }
    elif app_name == 'dropbox':
        return {
            'code': code,
            'grant_type': 'authorization_code',
            'client_id': DB_KEY,
            'client_secret': DB_SECRET,
            'redirect_uri': REDIRECT_URI_TEMPLATE.format(app=app_name),
        }


@app.route('/login/<app_name>')
def login(app_name: str):
    user_id = uuid.uuid4().hex
    url = LOGIN_URL[app_name]
    params = _get_login_params(app_name=app_name, user_id=user_id)
    authorize_url = url + urlencode(params)
    STORE[user_id] = {}
    result = jsonify({'user_id': user_id, 'authorize_url': authorize_url})
    return result


@app.route('/authorized/<app_name>')
def authorized(app_name: str):
    user_id = request.args.get('state')
    if user_id not in STORE:
        print('ERROR: unknown user')
        return make_response(''), 404

    code = request.args.get('code')
    headers = {
        'Accept': 'application/json',
    }
    params = _get_authorized_params(app_name=app_name, user_id=user_id, code=code)
    url = AUTHORIZED_URL[app_name]
    req = requests.post(url, params=params, headers=headers)
    if not req.ok:
        print('ERROR:', req.reason)
        return make_response(''), 404
    data = req.json()
    if 'access_token' not in data:
        print('ERROR: no token', req.content)
        return make_response(''), 404
    access_token = data['access_token']
    STORE[user_id]['access_token'] = access_token
    return HTML_TEMPLATE.render(
        title='Authentication successful',
        code=access_token,
        app='ESME',
        provider=app_name.capitalize(),
    )


@app.route('/tokens/')
@app.route('/tokens/<user_id>')
def tokens(user_id=None):
    if user_id is None:
        return make_response('', 404)
    if user_id not in STORE:
        return make_response('', 404)
    if 'access_token' not in STORE[user_id]:
        return make_response('', 404)
    access_token = STORE[user_id]['access_token']
    del STORE[user_id]['access_token']
    return jsonify({'token': access_token})


@app.route('/')
def default_route():
    return make_response('', 404)


if __name__ == '__main__':
    app.run(debug=True)
