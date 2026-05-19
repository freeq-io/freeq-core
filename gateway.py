from flask import Flask, jsonify, request
import time

app = Flask(__name__)

@app.route('/')
def home():
    return "<h1>FreeQ + SpanSafe POC Gateway</h1><p>Quantum-Safe Tunnel ACTIVE</p>"

@app.route('/risk', methods=['POST'])
def receive_risk():
    data = request.json
    print("🔒 Received secure risk score:", data)
    return jsonify({"status": "received", "risk": data.get("risk", "UNKNOWN")})

@app.route('/ota', methods=['GET'])
def ota_proxy():
    return jsonify({"presigned_url": "https://your-bucket.s3.amazonaws.com/firmware/test.bin", "secured": True})

if __name__ == '__main__':
    print("🚀 FreeQ Mock Gateway running on http://localhost:8080")
    app.run(host='0.0.0.0', port=8080)
