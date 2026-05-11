#!/usr/bin/env python3
"""
CalcPwn - A calculator service with eval() RCE vulnerability.

Endpoints:
  POST /api/store   - Store a secret (checker stores flags here)
  GET  /api/get     - Retrieve a secret by token
  POST /api/calc    - Calculator with eval() — VULNERABLE to RCE
  GET  /api/list    - List all secret tokens (public)
  GET  /health      - Health check
"""
import os
import uuid
import json
import re
from flask import Flask, request, jsonify

app = Flask(__name__)

# File-based secret storage
SECRETS_DIR = "/app/secrets"
os.makedirs(SECRETS_DIR, exist_ok=True)


@app.route("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/api/store", methods=["POST"])
def store_secret():
    data = request.json or {}
    secret = data.get("secret", "")
    owner = data.get("owner", "anonymous")
    if not secret:
        return jsonify({"error": "secret required"}), 400

    token = uuid.uuid4().hex[:16]
    entry = {"secret": secret, "owner": owner, "token": token}
    with open(os.path.join(SECRETS_DIR, f"{token}.json"), "w") as f:
        json.dump(entry, f)

    return jsonify({"token": token, "owner": owner}), 201


@app.route("/api/get")
def get_secret():
    token = request.args.get("token", "")
    if not token:
        return jsonify({"error": "token required"}), 400

    # Sanitize token (only hex chars)
    if not re.match(r'^[a-f0-9]+$', token):
        return jsonify({"error": "invalid token"}), 400

    filepath = os.path.join(SECRETS_DIR, f"{token}.json")
    if not os.path.exists(filepath):
        return jsonify({"error": "not found"}), 404

    with open(filepath) as f:
        entry = json.load(f)
    return jsonify(entry)


@app.route("/api/list")
def list_secrets():
    tokens = []
    for fname in os.listdir(SECRETS_DIR):
        if fname.endswith(".json"):
            filepath = os.path.join(SECRETS_DIR, fname)
            with open(filepath) as f:
                entry = json.load(f)
            tokens.append({"token": entry["token"], "owner": entry["owner"]})
    return jsonify(tokens)


# VULNERABLE: eval() on user input allows arbitrary code execution
@app.route("/api/calc", methods=["POST"])
def calc():
    data = request.json or {}
    expr = data.get("expr", "")
    if not expr:
        return jsonify({"error": "expr required"}), 400

    try:
        result = eval(expr)  # VULNERABLE!
        return jsonify({"expr": expr, "result": str(result)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8081, debug=True)
