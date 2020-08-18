import os, random, string, hashlib, urllib, base64, jwt
from oauthlib.oauth2 import WebApplicationClient
from expiringdict import ExpiringDict

from flask_cors import CORS
from flask import Flask, request, abort, redirect, jsonify
app = Flask(__name__)
CORS(app)

authorization_requests = ExpiringDict(max_len=100, max_age_seconds=600)
tokens = {}

def randomstring(n):
   randlst = [random.choice(string.ascii_letters + string.digits) for i in range(n)]
   return ''.join(randlst)

def unauthorized():
    return jsonify({'message': 'Hello, World'})

def authorized(token):
    return jsonify({'hermes_token': token, 'message': 'authorized'})

@app.route("/")
def hello():
    global tokens
    print(request)
    auth_header = request.headers.get('Authorization')
    if (auth_header == None):
        return unauthorized()

    splitted_auth_header = auth_header.split(' ')
    if (splitted_auth_header[0] != 'Bearer'):
        return unauthorized()
    
    token = jwt.decode(splitted_auth_header[1], verify=False)
    sub = token.get('sub')

    hermes_token = tokens[sub]
    if (hermes_token == None):
        return unauthorized()

    return authorized(hermes_token)

@app.route("/authorize")
def auth_request():
    global authorization_requests

    state = randomstring(128)
    nonce = randomstring(128)
    code_verifier = randomstring(128)
    code_challenge_raw = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(code_challenge_raw).decode('utf-8').replace('=', '')

    authorization_requests[state] = { 'state': state, 'nonce': nonce, 'code_challenge': code_challenge, 'code_verifier': code_verifier }
    print(authorization_requests[state])

    oauth = WebApplicationClient(os.environ.get("AUTH0_CLIENT_ID"))
    url, headers, body = oauth.prepare_authorization_request(
        f'https://{os.environ.get("AUTH0_DOMAIN")}/authorize',
        redirect_url=os.environ.get("AUTH0_REDIRECT_URL"),
        scope=os.environ.get("HERMES_SCOPE"),
        audience=os.environ.get("HERMES_AUDIENCE"),
        state=state,
        nonce=nonce,
        code_challenge=code_challenge,
        code_challenge_method='S256')

    print(url)
    return redirect(url)

@app.route("/callback")
def auth_callback():
    global authorization_requests
    global tokens
    print(request.args)
    print(authorization_requests)

    state = request.args.get('state')
    authorization_request = authorization_requests.pop(state)

    oauth = WebApplicationClient(os.environ.get("AUTH0_CLIENT_ID"))
    url, headers, body = oauth.prepare_token_request(
        f'https://{os.environ.get("AUTH0_DOMAIN")}/oauth/token',
        authorization_response=request.url,
        state=authorization_request.get('state'),
        code_verifier=authorization_request.get('code_verifier'),
        redirect_url=os.environ.get("AUTH0_REDIRECT_URL"))

    print(url)
    print(headers)
    print(body)

    req = urllib.request.Request(url, body.encode(), headers=headers)
    with urllib.request.urlopen(req) as res:
        response = oauth.parse_request_body_response(res.read())
        token = jwt.decode(response.get('access_token'), verify=False)
        tokens[token.get('sub')] = token

    return 'OK'
    
if __name__ == "__main__":
    app.run()