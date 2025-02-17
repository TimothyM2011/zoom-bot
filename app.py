import hmac
import hashlib
import json
from flask import Flask, request, jsonify

app = Flask(__name__)

# Replace with your secret token (Zoom generates this)
WEBHOOK_SECRET_TOKEN = 'S-ifzDhFRtetG9iKj43ZDg'

@app.route("/zoom_webhook", methods=["POST"])
def zoom_webhook():
    data = request.json

    # Handle the CRC challenge
    if data["event"] == "endpoint.url_validation":
        plain_token = data["payload"]["plainToken"]
        encrypted_token = hmac.new(
            WEBHOOK_SECRET_TOKEN.encode('utf-8'),
            plain_token.encode('utf-8'),
            hashlib.sha256
        ).hexdigest()

        return jsonify({
            "plainToken": plain_token,
            "encryptedToken": encrypted_token
        }), 200

    # Handle other events (process the payload)
    print("Received Event:", data)
    return jsonify({"message": "Received"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=10000)
