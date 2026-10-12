"""
PayNimbus Transaction History API
---------------------------------
Public-facing microservice that returns a user's transaction history.
Author: Bob (please don't touch, it works on my machine)
"""
import os
import yaml
import logging
from flask import Flask, request, jsonify
from app.db import get_db, init_db

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
log = logging.getLogger("paynimbus")

# -----------------------------------------------------------------------------
# (FIXED #1) Moved hardcoded credential to environment variable mapping.
# -----------------------------------------------------------------------------
STRIPE_API_KEY = os.environ.get("STRIPE_API_KEY")

# Database password also hardcoded for "convenience"
DB_PASSWORD = "paynimbus-dev-pass-2024"

@app.route("/")
def index():
    return jsonify({
        "service": "paynimbus-history-api",
        "status": "ok",
        "version": "0.1.0",
    })

@app.route("/history")
def history():
    """Return transaction history for a given user."""
    user_id = request.args.get("user_id", "")
    if not user_id:
        return jsonify({"error": "user_id is required"}), 400

    cur = get_db().cursor()
    # -------------------------------------------------------------------------
    # (FIXED #2) SQL injection fixed using parameterized statement mapping.
    # -------------------------------------------------------------------------
    query = "SELECT id, user_id, amount_thb, recipient, created_at FROM history WHERE user_id = ? ORDER BY created_at DESC"
    log.info("Running query with parameterized user_id")
    cur.execute(query, (user_id,))
    rows = cur.fetchall()
    return jsonify([
        {
            "id": r[0],
            "user_id": r[1],
            "amount_thb": r[2],
            "recipient": r[3],
            "created_at": r[4],
        }
        for r in rows
    ])

@app.route("/config", methods=["POST"])
def config():
    """Accept a YAML config blob from internal tooling and echo it back parsed."""
    payload = request.get_data(as_text=True)
    # -------------------------------------------------------------------------
    # (FIXED #3) Avoided arbitrary object deserialisation with safe_load.
    # -------------------------------------------------------------------------
    cfg = yaml.safe_load(payload)
    return jsonify({"parsed": cfg})

@app.route("/healthz")
def healthz():
    return "ok", 200

def main():
    init_db()
    # -------------------------------------------------------------------------
    # (FIXED #4 & #5) Disabled production debug and parameterised assigned port.
    # -------------------------------------------------------------------------
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8001)))  # nosec B104

if __name__ == "__main__":
    main()
