from flask import Flask, request, jsonify
from datetime import datetime, timedelta, timezone
import hmac
import hashlib
import time

app = Flask(__name__)

# In real life: use a DB.
# Each user has a shared key and subscription expiry.
USERS = {
    "user123": {
        "shared_key": b"THIS_IS_A_32_BYTE_MINIMUM_SECRET_KEY",
        "subscription_expires_at": datetime.now(timezone.utc) + timedelta(days=7),
    }
}

def compute_hmac_hex(key: bytes, message: str) -> str:
    """HMAC-SHA512(key, message) as lowercase hex string."""
    mac = hmac.new(key, message.encode("utf-8"), hashlib.sha512)
    return mac.hexdigest()

def verify_hmac(key: bytes, message: str, tag_hex: str) -> bool:
    expected = compute_hmac_hex(key, message)
    # constant-time compare
    return hmac.compare_digest(expected, tag_hex)

@app.post("/check_status")
def check_status():
    data = request.get_json(force=True, silent=True) or {}
    user_id = data.get("user_id")
    timestamp = data.get("timestamp")
    tag = data.get("tag")

    if not user_id or timestamp is None or not tag:
        return jsonify({"error": "invalid request"}), 400

    user = USERS.get(user_id)
    if user is None:
        return jsonify({"error": "unknown user"}), 401

    key = user["shared_key"]

    # Reconstruct canonical message for verification
    path = "/check_status"
    canonical = f"{user_id}|{timestamp}|{path}"

    if not verify_hmac(key, canonical, tag):
        return jsonify({"error": "invalid hmac"}), 401

    # Optional: timestamp window check (e.g. 5 minutes)
    now_secs = int(time.time())
    # if abs(now_secs - int(timestamp)) > 300:
    #     return jsonify({"error": "stale request"}), 401

    now = datetime.now(timezone.utc)
    expires_at = user["subscription_expires_at"]
    active = now <= expires_at

    active_int = 1 if active else 0
    expires_at_str = expires_at.isoformat()
    server_time = now_secs

    # Build response
    resp = {
        "user_id": user_id,
        "active": active,
        "expires_at": expires_at_str,
        "server_time": server_time,
    }

    # Canonical string for response HMAC
    resp_path = "/check_status_response"
    canonical_resp = f"{user_id}|{active_int}|{expires_at_str}|{server_time}|{resp_path}"
    resp_tag = compute_hmac_hex(key, canonical_resp)
    resp["tag"] = resp_tag

    return jsonify(resp), 200


if __name__ == "__main__":
    # dev mode, do NOT use in production directly
    app.run(host="0.0.0.0", port=8000, debug=True)
