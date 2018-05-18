# coding=utf-8

import os
import uuid

import jinja2
from dropbox import DropboxOAuth2Flow
from flask import Flask, jsonify, make_response, request

SESSION = {}
APP_SECRET = os.getenv('app_secret', None)
REDIRECT_URI = os.getenv('redirect_uri', None)
DB_KEY = os.getenv('db_key', None)
DB_SECRET = os.getenv('db_secret', None)

for val_name in {'APP_SECRET', 'REDIRECT_URI', 'DB_KEY', 'DB_SECRET'}:
    if not globals()[val_name]:
        raise ValueError(f'missing env value: {val_name}')

app = Flask('db_auth')
app.secret_key = os.getenv('app_secret')

latex_jinja_env = jinja2.Environment(
    block_start_string='\BLOCK{',
    block_end_string='}',
    variable_start_string='\VAR{',
    variable_end_string='}',
    comment_start_string='\#{',
    comment_end_string='}',
    line_statement_prefix='%%',
    line_comment_prefix='%#',
    trim_blocks=True,
    autoescape=False,
    loader=jinja2.FileSystemLoader(os.path.abspath('.'))
)

template = latex_jinja_env.get_template('index.html')


@app.route('/dropbox/login')
def dropbox_auth_start():
    print('FUNC dropbox_auth_start FUNC')
    if not all([REDIRECT_URI, DB_KEY, DB_SECRET]):
        print('missing config value')
        return make_response('', 404)
    global SESSION
    user_id = uuid.uuid4().hex
    print('user id', user_id)
    session_dict = {}
    flow = DropboxOAuth2Flow(
        DB_KEY,
        DB_SECRET,
        REDIRECT_URI,
        session_dict,
        'dropbox-auth-csrf-token'
    )
    print('flow', flow)
    authorize_url = flow.start()
    print('authorize_url', authorize_url)
    token = session_dict['dropbox-auth-csrf-token']
    print('token', token)
    SESSION[user_id] = session_dict
    SESSION[user_id]['flow'] = flow
    SESSION[user_id]['token'] = token
    print('SESSION', SESSION)
    result = jsonify({'user_id': user_id, 'authorize_url': authorize_url})
    print('result', result)
    return result


@app.route('/dropbox/authorized')
def dropbox_authorized():
    print('FUNC dropbox_authorized FUNC')
    global SESSION
    print('SESSION', SESSION)
    token = request.args.get('state')
    print('token', token)
    for session in SESSION.values():
        print('session value', session)
        print('session["token"]', session['token'])
        if session['token'] == token:
            flow = session['flow']
            print('flow', flow)
            assert isinstance(flow, DropboxOAuth2Flow)
            user_token = flow.finish(request.args).access_token
            session['user_token'] = user_token
            return template.render(title='Authentication successful', code=user_token, app='ESME', provider='Dropbox')

    print('404')
    return make_response('', 404)


@app.route('/tokens/')
@app.route('/tokens/<user_id>')
def tokens(user_id=None):
    global SESSION
    if user_id is None:
        return make_response('', 404)
    if user_id not in SESSION:
        return make_response('', 404)
    if 'user_token' not in SESSION[user_id]:
        return make_response('', 404)
    user_token = SESSION[user_id]['user_token']
    del SESSION[user_id]['user_token']
    return jsonify({'token': user_token})


@app.route('/')
def default_route():
    return make_response('', 404)


if __name__ == '__main__':
    app.run(debug=True)
