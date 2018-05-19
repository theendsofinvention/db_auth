# coding=utf-8

import os
import uuid
from urllib.parse import urlencode

import requests
from dropbox import DropboxOAuth2Flow
from flask import Flask, jsonify, make_response, request

from _config import DB_KEY, DB_SECRET, GH_KEY, GH_SECRET, HTML_TEMPLATE, REDIRECT_URI_TEMPLATE, STORE

app = Flask('db_auth')
app.secret_key = os.getenv('app_secret')


@app.route('/dropbox/login')
def dropbox_auth_start():
    user_id = uuid.uuid4().hex
    session_dict = {}
    flow = DropboxOAuth2Flow(
        DB_KEY,
        DB_SECRET,
        REDIRECT_URI_TEMPLATE.format(app='dropbox'),
        session_dict,
        'dropbox-auth-csrf-token'
    )
    authorize_url = flow.start()
    state = session_dict['dropbox-auth-csrf-token']
    STORE[user_id] = session_dict
    STORE[user_id]['flow'] = flow
    STORE[user_id]['state'] = state
    result = jsonify({'user_id': user_id, 'authorize_url': authorize_url})
    return result


@app.route('/dropbox/authorized')
def dropbox_authorized():
    state = request.args.get('state')
    for user_store in STORE.values():
        if user_store['state'] == state:
            flow = user_store['flow']
            assert isinstance(flow, DropboxOAuth2Flow)
            access_token = flow.finish(request.args).access_token
            user_store['access_token'] = access_token
            return HTML_TEMPLATE.render(
                title='Authentication successful',
                code=access_token,
                app='ESME',
                provider='Dropbox',
            )

    return make_response('', 404)


@app.route('/github/login')
def github_start():
    user_id = uuid.uuid4().hex
    base_url = r'https://github.com/login/oauth/authorize?'
    params = {
        'client_id': GH_KEY,
        'redirect_uri': REDIRECT_URI_TEMPLATE.format(app='github'),
        'scope': 'repo',
        'state': user_id,
    }
    authorize_url = base_url + urlencode(params)
    STORE[user_id] = {}
    result = jsonify({'user_id': user_id, 'authorize_url': authorize_url})
    return result


@app.route('/github/authorized')
def github_authorized():
    user_id = request.args.get('state')
    if user_id not in STORE:
        print('ERROR: unknown user')
        return make_response(''), 404

    code = request.args.get('code')
    headers = {
        'Accept': 'application/json',
    }
    params = {
        'client_id': GH_KEY,
        'client_secret': GH_SECRET,
        'code': code,
        'redirect_uri': REDIRECT_URI_TEMPLATE.format(app='github'),
        'state': user_id,
    }
    req = requests.post(r'https://github.com/login/oauth/access_token', params=params, headers=headers)
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
        provider='Github',
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
