# coding=utf-8

import os
import jinja2

STORE = {}
APP_SECRET = os.getenv('app_secret', None)
REDIRECT_URI_TEMPLATE = os.getenv('redirect_uri_template', None)
DB_KEY = os.getenv('db_key', None)
DB_SECRET = os.getenv('db_secret', None)
GH_KEY = os.getenv('gh_key', None)
GH_SECRET = os.getenv('gh_secret', None)

for val_name in {'APP_SECRET', 'REDIRECT_URI_TEMPLATE', 'DB_KEY', 'DB_SECRET', 'GH_KEY', 'GH_SECRET'}:
    if not globals()[val_name]:
        raise ValueError(f'missing env value: {val_name}')

jinja_env = jinja2.Environment(
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

HTML_TEMPLATE = jinja_env.get_template('index.html')
