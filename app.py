# coding=utf-8

import os

# from flask_api import FlaskAPI, request
import jinja2
from dropbox import DropboxOAuth2Flow
from flask import Flask, jsonify, make_response, request, session

TOKENS = {}
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
    if not all([REDIRECT_URI, DB_KEY, DB_SECRET]):
        return make_response('', 404)
    authorize_url = DropboxOAuth2Flow(
        DB_KEY,
        DB_SECRET,
        REDIRECT_URI,
        session,
        'dropbox-auth-csrf-token'
    ).start()
    user_id = session['dropbox-auth-csrf-token']
    return jsonify({'user_id': user_id, 'authorize_url': authorize_url})


@app.route('/tokens/')
@app.route('/tokens/<uuid>')
def tokens(uuid=None):
    if uuid is None:
        return make_response('', 404)
    if uuid not in TOKENS:
        return make_response('', 404)
    token = TOKENS[uuid]
    del TOKENS[uuid]
    return jsonify({'token': token})


@app.route('/dropbox/authorized')
def dropbox_authorized():
    global TOKENS
    code = request.args.get('code')
    uuid = request.args.get('state')
    TOKENS[uuid] = code
    return template.render(title='Authentication successful', code=code, app='ESME', provider='Dropbox')


@app.route('/')
def default_route():
    return make_response('', 404)


if __name__ == '__main__':
    app.run(debug=True)
