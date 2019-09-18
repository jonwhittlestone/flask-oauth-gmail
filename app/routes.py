import os
import flask
from flask import session
import requests

import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery

from app import app

APP_DIR = os.path.dirname(os.path.realpath(__file__))
# This variable specifies the name of a file that contains
# the OAuth 2.0 information for this application,
# including its client_id and client_secret.
CLIENT_SECRETS_FILE = "client_secret.json"
CLIENT_SECRETS_FILEPATH = f'{APP_DIR}/{CLIENT_SECRETS_FILE}'

# This OAuth 2.0 access scope allows for full read/write access 
# to the authenticated user's account and requires 
# requests to use an SSL connection.

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
API_SERVICE_NAME = 'gmail'
API_VERSION = 'v1'

app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

@app.route('/')
def index():
    return print_index_table()

def print_index_table():
    return ('<table>' +
          '<tr><td><a href="/test">Test an API request</a></td>' +
          '<td>Submit an API request and see a formatted JSON response. ' +
          '    Go through the authorization flow if there are no stored ' +
          '    credentials for the user.</td></tr>' +
          '<tr><td><a href="/authorize">Test the auth flow directly</a></td>' +
          '<td>Go directly to the authorization flow. If there are stored ' +
          '    credentials, you still might not be prompted to reauthorize ' +
          '    the application.</td></tr>' +
          '<tr><td><a href="/revoke">Revoke current credentials</a></td>' +
          '<td>Revoke the access token associated with the current user ' +
          '    session. After revoking credentials, if you go to the test ' +
          '    page, you should see an <code>invalid_grant</code> error.' +
          '</td></tr>' +
          '<tr><td><a href="/clear">Clear Flask session credentials</a></td>' +
          '<td>Clear the access token currently stored in the user session. ' +
          '    After clearing the token, if you <a href="/test">test the ' +
          '    API request</a> again, you should go back to the auth flow.' +
          '</td></tr></table>')

@app.route('/test')
def test_api_request():
    if 'credentials' not in session:
        return flask.redirect('authorize')

    credentials = session.get('credentials', {})
    credentials = google.oauth2.credentials.Credentials(
        credentials.get('token'),
        refresh_token=credentials.get('refresh_token'),
        token_uri=credentials.get('token_uri'),
        client_id=credentials.get('client_id'),
        client_secret=credentials.get('client_secret'),
        scopes=credentials.get('scopes'))

    service = googleapiclient.discovery.build(
        API_SERVICE_NAME, API_VERSION, credentials=credentials
    )

    results = service.users().labels().get(userId='me', id='INBOX').execute()
    # labels = results.get('labels', [])
    

    session['credentials'] = credentials_to_dict(credentials)
    return flask.jsonify({'GMAIL INBOX COUNT': results.get('messagesTotal')})

@app.route('/authorize')
def authorize():
    ''' Step 1, 2 and 3''' 

    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILEPATH, scopes=SCOPES)
    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true'
    )
    session['state'] = state
    return flask.redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    '''
        Step 4 Getting the auth code and
        Steo 5 Exchange auth code for refresh/access tokens
    '''

    state = session['state']
    flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILEPATH, scopes=SCOPES, state=state
    )

    flow.redirect_uri = flask.url_for('oauth2callback', _external=True)
    # use the authorization server's response to fetch OAuth 2.0
    # token

    # Step 5 - get tokens, and store in session
    authorization_response = flask.request.url
    flow.fetch_token(authorization_response=authorization_response)
    credentials = flow.credentials
    session['credentials'] = credentials_to_dict(credentials)
    
    return flask.redirect(flask.url_for('test_api_request'))


def credentials_to_dict(credentials):
    debug = credentials
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}

@app.route('/clear')
def clear_credentials():
    if 'credentials' in session:
        del session['credentials']
    return (f'Credentials have been cleared.<br><br>{print_index_table()}')

@app.route('/revoke')
def revoke():
    if 'credentials' not in session:
        return ('You You need to <a href="/authorize">authorize</a> before testing the code to revoke credentials.')
    
    credentials = google.oauth2.credentials.Credentials(
        **session['credentials'])

    revoke = requests.post('https://accounts.google.com/o/oauth2/revoke',
        params={'token': credentials.token},
        headers = {'content-type': 'application/x-www-form-urlencoded'})

    status_code = getattr(revoke, 'status_code')
    if status_code == 200:
        return('Credentials successfully revoked.' + print_index_table())
    else:
        return(f'An error occurred.{print_index_table()}')
