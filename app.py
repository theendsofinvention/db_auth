# coding=utf-8

import os

from dropbox import DropboxOAuth2Flow
from flask import Flask, redirect, request

app = Flask(__name__)
app.secret_key = os.getenv('app_secret')


def get_dropbox_auth_flow(web_app_session):
    redirect_uri = 'http://localhost/dropbox/authorized'
    return DropboxOAuth2Flow(
        os.getenv('db_key'),
        os.getenv('db_secret'),
        redirect_uri,
        web_app_session,
        'dropbox-auth-csrf-token'
    )


@app.route('/dropbox/login')
def dropbox_auth_start():
    authorize_url = get_dropbox_auth_flow({}).start()
    return redirect(authorize_url)


@app.route('/dropbox/authorized')
def dropbox_authorized():
    code = request.args.get('code')
    msg = f'Your token for using ESME with your Dropbox account is:\n\n{code}\n\nKeep it secret!'
    return msg


if __name__ == '__main__':
    app.run()
