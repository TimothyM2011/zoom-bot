import hmac
import hashlib
import logging
import sqlite3
import urllib.parse
import requests
import os
from dotenv import load_dotenv  # Import dotenv
from flask import Flask, request, jsonify, redirect
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow

# ✅ Load environment variables from the .env file
load_dotenv()

# ✅ Load sensitive information from environment variables
WEBHOOK_SECRET_TOKEN = os.getenv("WEBHOOK_SECRET_TOKEN")
ZOOM_CLIENT_ID = os.getenv("ZOOM_CLIENT_ID")
ZOOM_CLIENT_SECRET = os.getenv("ZOOM_CLIENT_SECRET")
ZOOM_REDIRECT_URI = os.getenv("ZOOM_REDIRECT_URI")
SPREADSHEET_ID = os.getenv("SPREADSHEET_ID")

# ✅ Setup logging
logging.basicConfig(level=logging.DEBUG)

# ✅ Database setup
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

# ✅ Google Sheets Integration
SCOPES = ['https://www.googleapis.com/auth/spreadsheets']
RANGE_NAME = 'Sheet1!A1:D1'

def get_sheets_service():
    flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
    creds = flow.run_local_server(port=0)
    service = build('sheets', 'v4', credentials=creds)
    return service

def log_violation_to_sheets(user_id, violation_type, warning_count):
    try:
        service = get_sheets_service()
        values = [[user_id, violation_type, warning_count]]
        body = {'values': values}
        service.spreadsheets().values().append(
            spreadsheetId=SPREADSHEET_ID,
            range=RANGE_NAME,
            valueInputOption="RAW",
            body=body
        ).execute()
    except Exception as e:
        logging.error(f"Failed to log to Google Sheets: {e}")

# ✅ Validate Zoom webhook CRC
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

@app.route('/zoom-webhook', methods=['POST'])
def zoom_webhook():
    crc_response = validate_crc(request)
    if crc_response:
        return crc_response

    data = request.json
    logging.info(f"Received webhook data: {data}")

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
    logging.info(f"Admin notified: User {user_id} violated rule '{violation_type}'. Warning count: {warning_count}")
    send_message_to_chat(f"User {user_id} violated rule: {violation_type}. Warning count: {warning_count}", user_id)

def send_message_to_chat(message, user_id):
    bot_token = os.getenv("ZOOM_BOT_TOKEN")
    chat_id = os.getenv("ZOOM_ADMIN_CHAT_ID")

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
        logging.info("Message sent successfully!")
    else:
        logging.error(f"Failed to send message: {response.status_code}, {response.text}")

    return response.json()

### ✅ OAuth Flow for Zoom Authentication ###
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
        logging.info("OAuth Authorization Success")
        return jsonify({"access_token": access_token})
    else:
        logging.error("OAuth token exchange failed")
        return jsonify({"error": "OAuth token exchange failed"}), 400

if __name__ == '__main__':
    port = int(10000)
    app.run(host="0.0.0.0", port=port)
