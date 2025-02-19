import os
import requests
from requests.auth import HTTPBasicAuth
from flask import request, jsonify

def oauth_callback():
    code = request.args.get("code")
    if not code:
        return jsonify({"error": "Missing authorization code"}), 400

    # Load environment variables
    redirect_uri = os.getenv("ZOOM_REDIRECT_URI")
    client_id = os.getenv("ZOOM_CLIENT_ID")
    client_secret = os.getenv("ZOOM_CLIENT_SECRET")

    if not client_id or not client_secret or not redirect_uri:
        return jsonify({"error": "Missing environment variables"}), 400

    token_url = "https://zoom.us/oauth/token"
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri
    }

    response = requests.post(token_url, data=payload, auth=HTTPBasicAuth(client_id, client_secret))

    # Print Zoom's full response for debugging
    print("Zoom Response:", response.status_code, response.text)  

    if response.status_code == 200:
        tokens = response.json()
        access_token = tokens.get("access_token")
        refresh_token = tokens.get("refresh_token")
        return jsonify({"message": "OAuth Success", "access_token": access_token, "refresh_token": refresh_token})
    else:
        return jsonify({"error": "OAuth token exchange failed", "details": response.text}), 400
