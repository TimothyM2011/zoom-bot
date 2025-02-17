from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route("/", methods=["GET"])
def home():
    return "Zoom Bot is Running!"

@app.route("/zoom_webhook", methods=["POST"])
def zoom_webhook():
    data = request.json
    
    # Zoom's validation check
    if "event" in data and data["event"] == "endpoint.url_validation":
        return jsonify({
            "plainToken": data["payload"]["plainToken"]
        }), 200

    print("Received Event:", data)
    return jsonify({"message": "Received"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
