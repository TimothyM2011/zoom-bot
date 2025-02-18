import hmac
import hashlib
import logging
import sqlite3
from flask import Flask, request, jsonify
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow

app = Flask(__name__)

# Replace with your secret token (Zoom generates this)
WEBHOOK_SECRET_TOKEN = 'OFjuyO_6StaNC6oc0xvpWA'

# Setup logging
logging.basicConfig(level=logging.DEBUG)

# Dummy Database for Storing Violations (you can switch to a real DB like Firebase)
conn = sqlite3.connect('violations.db', check_same_thread=False)
cursor = conn.cursor()

# Create table for violations if not exists
cursor.execute('''
CREATE TABLE IF NOT EXISTS violations (
    user_id TEXT,
    violation_type TEXT,
    warning_count INTEGER
)
''')
conn.commit()

# Example of Google Sheets Integration (or you can use another method like email notifications)
# Assuming you have set up Google Sheets API credentials
SCOPES = ['https://www.googleapis.com/auth/spreadsheets']
SPREADSHEET_ID = '10kU-K2MejZMzsUPjAX-ZN4aN4SoO9fjcuMXaQYz0b2g'
RANGE_NAME = 'Sheet1!A1:D1'

# OAuth flow for Google Sheets
def get_sheets_service():
    flow = InstalledAppFlow.from_client_secrets_file(
        'credentials.json', SCOPES)
    creds = flow.run_local_server(port=0)
    service = build('sheets', 'v4', credentials=creds)
    return service

def log_violation_to_sheets(user_id, violation_type, warning_count):
    service = get_sheets_service()
    values = [[user_id, violation_type, warning_count]]
    body = {
        'values': values
    }
    service.spreadsheets().values().append(
        spreadsheetId=SPREADSHEET_ID,
        range=RANGE_NAME,
        valueInputOption="RAW",
        body=body
    ).execute()

def validate_signature(request):
    # Retrieve the request body and headers
    request_body = request.get_data(as_text=True)
    zoom_signature = request.headers.get('x-zm-signature')
    zoom_time = request.headers.get('x-zm-timestamp')

    # Create a signature string using the secret token and the body of the request
    message = zoom_time + request_body
    computed_signature = hmac.new(
        WEBHOOK_SECRET_TOKEN.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()

    # Compare the computed signature with the signature sent by Zoom
    return hmac.compare_digest(computed_signature, zoom_signature)

@app.route('/zoom-webhook', methods=['POST'])
def zoom_webhook():
    # Validate the webhook signature before processing any data
    if not validate_signature(request):
        return jsonify({"message": "Invalid signature"}), 403

    data = request.json
    logging.info(f"Received data: {data}")

    event = data.get("event")
    user_id = data.get("payload", {}).get("object", {}).get("user_id")
    violation_type = None
    warning_count = None

    # Example: Check for message events and ban violations
    if event == "chat.message.sent":
        message = data.get("payload", {}).get("object", {}).get("message")
        if "call" in message or "zoom.us/j/" in message:  # Detect call-related terms
            violation_type = "No Calling"
            warning_count = process_violation(user_id, violation_type)

    elif event == "chat.message.updated":
        message = data.get("payload", {}).get("object", {}).get("message")
        if "call" in message or "zoom.us/j/" in message:  # Detect call-related terms
            violation_type = "No Calling"
            warning_count = process_violation(user_id, violation_type)

    if violation_type:
        log_violation_to_sheets(user_id, violation_type, warning_count)

        # Notify Admin (this can be an email or direct message)
        send_admin_notification(user_id, violation_type, warning_count)

    return jsonify({"status": "success"}), 200

def process_violation(user_id, violation_type):
    # Check if user already has violations
    cursor.execute("SELECT warning_count FROM violations WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()

    if row:
        warning_count = row[0] + 1
        cursor.execute("UPDATE violations SET warning_count = ? WHERE user_id = ?", (warning_count, user_id))
    else:
        warning_count = 1
        cursor.execute("INSERT INTO violations (user_id, violation_type, warning_count) VALUES (?, ?, ?)", (user_id, violation_type, warning_count))

    conn.commit()

    # If 3 warnings, notify admin to potentially ban user
    if warning_count >= 3:
        return warning_count  # You can automate banning actions here

    return warning_count

def send_admin_notification(user_id, violation_type, warning_count):
    # Here we send a notification to admin (email or other method)
    print(f"Admin notified: User {user_id} violated rule '{violation_type}'. Warning count: {warning_count}")
    # You can add email notification logic here, or push notifications to admin

if __name__ == '__main__':
    app.run(port=5000)
