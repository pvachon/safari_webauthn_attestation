#!/usr/bin/env python3

from flask import Flask, send_from_directory, jsonify, request
import os
import base64
import webauthn

app = Flask(__name__, static_url_path='')

user_cred = {
    'user_name': 'sample@me.com',
    'display_name': 'John K. Sample',
    'user_id': os.urandom(8),
}

last_challenge = os.urandom(32)

site_config = {
    'relying_party_name': 'webauthnsample.com',
}


@app.route('/')
def index():
    '''
    Special route to serve the index page.
    '''
    return send_from_directory('page', 'index.html')


@app.route('/page/<path:path>')
def serve_page(path):
    '''
    Serve any referenced content for the front page
    '''
    return send_from_directory('page', path)


@app.route('/api/login_info', methods=['GET', 'POST'])
def login_info():
    '''
    Set up or retrieve information on a webauthn credential
      GET - gets a current credential, if any
      POST - sets a credential, through enrollment
    '''
    if request.method == 'POST':
        content = request.get_json(force=True, cache=False)
        raw_attestation = content.get('attestation', '')
        ok = webauthn.check_attestation(base64.b64decode(raw_attestation), last_challenge, base64.b64decode(content.get('clientData')), user_cred)
        if ok:
            return jsonify(True)
        else:
            return "Attestation failure, aborting.", 400
    else:
        return jsonify({
            'credential': user_cred.get('credential', None),
            'displayName': user_cred['display_name'],
            'userName': user_cred['user_name'],
            'userId': base64.b64encode(user_cred['user_id']).decode('ascii'),
            'challenge': base64.b64encode(last_challenge).decode('ascii'),
            'relyingPartyName': site_config['relying_party_name']})

