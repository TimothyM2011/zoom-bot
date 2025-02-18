import hmac
import hashlib
import logging
import sqlite3
import urllib.parse
import requests
from flask import Flask, request, jsonify, redirect

from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
import re

app = Flask(__name__)

# Replace with your secret token (Zoom generates this)
WEBHOOK_SECRET_TOKEN = 'bJxRTcEpQWODaoRFfQ-6DQ'

# Zoom OAuth Credentials
ZOOM_CLIENT_ID = '62I52TceR228cm0hZmGBFQ'
ZOOM_CLIENT_SECRET = 'Cc4s6O2B8d280FDy25K2181OxVEiZvPH'
ZOOM_REDIRECT_URI = 'http://localhost:5000/oauth/callback'

# Setup logging
logging.basicConfig(level=logging.DEBUG)

# Dummy Database for Storing Violations
conn = sqlite3.connect('violations.db', check_same_thread=False)
cursor = conn.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS violations (
    user_id TEXT,
    violation_type TEXT,
    warning_count INTEGER
)
''')
conn.commit()

# Google Sheets Integration
SCOPES = ['https://www.googleapis.com/auth/spreadsheets']
SPREADSHEET_ID = '10kU-K2MejZMzsUPjAX-ZN4aN4SoO9fjcuMXaQYz0b2g'
RANGE_NAME = 'Sheet1!A1:D1'

# OAuth flow for Google Sheets
def get_sheets_service():
    flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
    creds = flow.run_local_server(port=0)
    service = build('sheets', 'v4', credentials=creds)
    return service

def log_violation_to_sheets(user_id, violation_type, warning_count):
    service = get_sheets_service()
    values = [[user_id, violation_type, warning_count]]
    body = {'values': values}
    service.spreadsheets().values().append(
        spreadsheetId=SPREADSHEET_ID,
        range=RANGE_NAME,
        valueInputOption="RAW",
        body=body
    ).execute()

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

        return jsonify({
            "plainToken": plain_token,
            "encryptedToken": encrypted_token
        }), 200

    return None

@app.route('/zoom-webhook', methods=['POST'])
def zoom_webhook():
    crc_response = validate_crc(request)
    if crc_response:
        return crc_response
    
    data = request.json
    logging.info(f"Received data: {data}")

    event = data.get("event")
    user_id = data.get("payload", {}).get("object", {}).get("user_id")
    violation_type, warning_count = None, None

    if event in ["chat.message.sent", "chat.message.updated"]:
        message = data.get("payload", {}).get("object", {}).get("message")
        violation_type, warning_count = evaluate_message(message, user_id)

    if violation_type:
        log_violation_to_sheets(user_id, violation_type, warning_count)
        send_admin_notification(user_id, violation_type, warning_count)

    return jsonify({"status": "success"}), 200

def evaluate_message(message, user_id):
    violation_type, warning_count = None, None

    if re.search(r"(call|zoom\.us\/j\/)", message, re.IGNORECASE):
        violation_type = "No Calling"
    elif re.search(r"(promotion|buy|discount|sale)", message, re.IGNORECASE):
        violation_type = "No Promotions"
    elif re.search(r"(nsfw|adult|explicit|porn|xxx)", message, re.IGNORECASE):
        violation_type = "No NSFW"
    elif re.search(r"(leak|private info|confidential)", message, re.IGNORECASE):
        violation_type = "Leaking Information"

    if violation_type:
        warning_count = process_violation(user_id, violation_type)

    return violation_type, warning_count

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

def send_admin_notification(user_id, violation_type, warning_count):
    print(f"Admin notified: User {user_id} violated rule '{violation_type}'. Warning count: {warning_count}")
    send_message_to_chat(f"User {user_id} violated rule: {violation_type}. Warning count: {warning_count}", user_id)

def send_message_to_chat(message, user_id):
    bot_token = 'your_zoom_bot_oauth_token'
    chat_id = 'your_admin_group_room_id'

    url = f"https://api.zoom.us/v2/chat/users/{bot_token}/messages"
    
    headers = {
        "Authorization": f"Bearer {bot_token}",
        "Content-Type": "application/json"
    }

    payload = {
        "message": message,
        "to_jid": "v1jsoyngf4risfasnxugohrq@xmpp.zoom.us",
        "to_channel": chat_id
    }

    response = requests.post(url, json=payload, headers=headers)

    if response.status_code == 200:
        print("Message sent successfully!")
    else:
        print(f"Failed to send message. Error: {response.status_code}, {response.text}")

    return response.json()

### OAuth Flow for Zoom Authentication ###

@app.route('/authorize')
def authorize():
    auth_url = (
        f"https://zoom.us/oauth/authorize"
        f"?response_type=code"
        f"&client_id={ZOOM_CLIENT_ID}"
        f"&redirect_uri={urllib.parse.quote(ZOOM_REDIRECT_URI)}"
    )
    return redirect(auth_url)

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
        access_token = response.json()['access_token']
        refresh_token = response.json()['refresh_token']
        print(f"Access Token: {access_token}")
        print(f"Refresh Token: {refresh_token}")
        return jsonify({"message": "OAuth Authorization Success", "access_token": access_token})
    else:
        return jsonify({"error": "OAuth token exchange failed"}), 400

@app.route('/refresh_token')
def refresh_access_token():
    refresh_token = request.args.get("refresh_token")
    
    token_url = "https://zoom.us/oauth/token"
    payload = {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token
    }
    auth = (ZOOM_CLIENT_ID, ZOOM_CLIENT_SECRET)
    response = requests.post(token_url, data=payload, auth=auth)

    if response.status_code == 200:
        return response.json()
    else:
        return jsonify({"error": "Failed to refresh token"}), 400

if __name__ == '__main__':
    app.run(port=5000)
