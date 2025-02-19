import hmac
import hashlib
import logging
import sqlite3
import urllib.parse
import requests
import os
import re
from dotenv import load_dotenv
from flask import Flask, request, jsonify, redirect

# ✅ Load environment variables
load_dotenv()

# ✅ Load sensitive info
WEBHOOK_SECRET_TOKEN = os.getenv("WEBHOOK_SECRET_TOKEN")
ZOOM_CLIENT_ID = os.getenv("ZOOM_CLIENT_ID")
ZOOM_CLIENT_SECRET = os.getenv("ZOOM_CLIENT_SECRET")
ZOOM_REDIRECT_URI = os.getenv("ZOOM_REDIRECT_URI")
SPREADSHEET_ID = os.getenv("SPREADSHEET_ID")
ZOOM_BOT_TOKEN = os.getenv("ZOOM_BOT_TOKEN")
ZOOM_ADMIN_CHAT_ID = os.getenv("ZOOM_ADMIN_CHAT_ID")

app = Flask(__name__)

# ✅ Database setup (Stores OAuth tokens & violations)
conn = sqlite3.connect('bot_data.db', check_same_thread=False)
cursor = conn.cursor()

cursor.execute(''' 
CREATE TABLE IF NOT EXISTS tokens (
    access_token TEXT,
    refresh_token TEXT,
    expires_at INTEGER
)
''')

cursor.execute(''' 
CREATE TABLE IF NOT EXISTS violations (
    user_id TEXT,
    violation_type TEXT,
    warning_count INTEGER
)
''')
conn.commit()

# ✅ OAuth Authorization Route
@app.route('/authorize')
def authorize():
    auth_url = (
        f"https://zoom.us/oauth/authorize"
        f"?response_type=code"
        f"&client_id={ZOOM_CLIENT_ID}"
        f"&redirect_uri={urllib.parse.quote(ZOOM_REDIRECT_URI)}"
    )
    return redirect(auth_url)

# ✅ OAuth Callback Route (Exchanges code for token)
@app.route('/oauth/callback')
def oauth_callback():
    code = request.args.get('code')
    token_url = "https://zoom.us/oauth/token"
    payload = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": ZOOM_REDIRECT_URI
    }
    auth = (ZOOM_CLIENT_ID, ZOOM_CLIENT_SECRET)

    response = requests.post(token_url, data=payload, auth=auth)

    if response.status_code == 200:
        tokens = response.json()
        store_tokens(tokens["access_token"], tokens["refresh_token"])
        return "Authorization successful! Bot is now active."
    return jsonify({"error": "OAuth token exchange failed"}), 400

# ✅ Store Tokens in Database
def store_tokens(access_token, refresh_token):
    cursor.execute("DELETE FROM tokens")
    cursor.execute("INSERT INTO tokens (access_token, refresh_token, expires_at) VALUES (?, ?, strftime('%s', 'now') + 3600)", 
                   (access_token, refresh_token))
    conn.commit()

# ✅ Get Stored Token
def get_access_token():
    cursor.execute("SELECT access_token, refresh_token, expires_at FROM tokens")
    row = cursor.fetchone()

    if not row:
        return None

    access_token, refresh_token, expires_at = row
    if int(expires_at) < int(os.popen('date +%s').read().strip()):  # Token expired
        return refresh_access_token(refresh_token)
    return access_token

# ✅ Refresh Access Token
def refresh_access_token(refresh_token):
    token_url = "https://zoom.us/oauth/token"
    payload = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token
    }
    auth = (ZOOM_CLIENT_ID, ZOOM_CLIENT_SECRET)

    response = requests.post(token_url, data=payload, auth=auth)

    if response.status_code == 200:
        new_tokens = response.json()
        store_tokens(new_tokens["access_token"], new_tokens["refresh_token"])
        return new_tokens["access_token"]
    return None

# ✅ Validate Webhook Signature
def validate_crc(request):
    data = request.json
    if 'event' not in data:
        return False
    
    if data['event'] == 'endpoint.url_validation':
        plain_token = data['payload']['plainToken']
        encrypted_token = hmac.new(
            WEBHOOK_SECRET_TOKEN.encode('utf-8'),
            plain_token.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()
        return jsonify({"plainToken": plain_token, "encryptedToken": encrypted_token}), 200
    return None

# ✅ Handle Webhooks
@app.route('/zoom-webhook', methods=['POST'])
def zoom_webhook():
    crc_response = validate_crc(request)
    if crc_response:
        return crc_response

    data = request.json
    logging.info(f"Received webhook data: {data}")

    event = data.get("event")
    user_id = data.get("payload", {}).get("object", {}).get("user_id")
    message = data.get("payload", {}).get("object", {}).get("message")

    # ✅ Send message to Zapier to check for violations
    violation_type = check_message_with_zapier(message)

    if violation_type:
        warning_count = process_violation(user_id, violation_type)
        log_violation_to_sheets(user_id, violation_type, warning_count)
        send_admin_notification(user_id, violation_type, warning_count)

    return jsonify({"status": "success"}), 200

# ✅ Send message to Zapier
def check_message_with_zapier(message):
    zapier_url = "https://interfaces.zapier.com/assets/web-components/zapier-interfaces/zapier-interfaces.esm.js"
    response = requests.post(zapier_url, json={"message": message})
    return response.json().get("violation")

# ✅ Process violation
def process_violation(user_id, violation_type):
    cursor.execute("SELECT warning_count FROM violations WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()

    if row:
        warning_count = row[0] + 1
        cursor.execute("UPDATE violations SET warning_count = ? WHERE user_id = ?", (warning_count, user_id))
    else:
        warning_count = 1
        cursor.execute("INSERT INTO violations (user_id, violation_type, warning_count) VALUES (?, ?, ?)", (user_id, violation_type, warning_count))

    conn.commit()
    return warning_count

# ✅ Notify Admin Group
def send_admin_notification(user_id, violation_type, warning_count):
    message = f"User {user_id} violated rule: {violation_type}. Warning count: {warning_count}"
    send_message_to_chat(message, ZOOM_ADMIN_CHAT_ID)

# ✅ Send Message to Zoom Chat
def send_message_to_chat(message, chat_id):
    access_token = get_access_token()
    url = f"https://api.zoom.us/v2/chat/users/me/messages"
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    payload = {
        "message": message,
        "to_channel": chat_id
    }

    response = requests.post(url, json=payload, headers=headers)
    return response.json()

# ✅ Run the Flask App
if __name__ == '__main__':
    port = int(10000)
    app.run(host="0.0.0.0", port=port)
