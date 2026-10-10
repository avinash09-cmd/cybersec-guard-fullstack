"""
app.py
------
CyberSecGuard Flask API — centralized backend for the dashboard.

Run with:
    python app.py

Serves the JavaScript dashboard at / and exposes JSON endpoints under /api/*
for the scanner, traffic analyzer, and password vault, all backed by MySQL.
"""

import os
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

from database import init_db, get_session, ScanResult, ScanPort, TrafficSession, TrafficAlert
import scanner
import sniffer
import password_tool

app = Flask(__name__, static_folder="../dashboard", static_url_path="")
CORS(app)

# In-memory session token -> Fernet key, so the master password itself is
# never stored and the derived key only lives as long as the process needs it.
_unlocked_sessions = {}


@app.route("/")
def dashboard():
    return send_from_directory(app.static_folder, "index.html")


# ---------------------------------------------------------------------------
# Scanner endpoints
# ---------------------------------------------------------------------------

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.get_json(force=True)
    target = data.get("target", "").strip()
    if not target:
        return jsonify({"error": "target is required"}), 400
    try:
        result = scanner.scan_and_store(target, data.get("ports"))
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scans", methods=["GET"])
def api_scans():
    db = get_session()
    try:
        scans = db.query(ScanResult).order_by(ScanResult.created_at.desc()).limit(20).all()
        out = []
        for s in scans:
            out.append({
                "id": s.id, "target": s.target, "engine": s.engine,
                "created_at": s.created_at.isoformat(),
                "ports": [{"port": p.port, "service": p.service, "banner": p.banner, "risk_note": p.risk_note}
                          for p in s.ports],
            })
        return jsonify(out)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Traffic analyzer endpoints
# ---------------------------------------------------------------------------

@app.route("/api/sniff", methods=["POST"])
def api_sniff():
    data = request.get_json(force=True) or {}
    duration = int(data.get("duration", 10))
    interface = data.get("interface")
    try:
        result = sniffer.capture_and_store(duration, interface)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/alerts", methods=["GET"])
def api_alerts():
    db = get_session()
    try:
        sessions = db.query(TrafficSession).order_by(TrafficSession.created_at.desc()).limit(20).all()
        out = []
        for s in sessions:
            out.append({
                "id": s.id, "engine": s.engine, "packet_count": s.packet_count,
                "created_at": s.created_at.isoformat(),
                "alerts": [{"type": a.alert_type, "message": a.message} for a in s.alerts],
            })
        return jsonify(out)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Password strength + vault endpoints
# ---------------------------------------------------------------------------

@app.route("/api/password/check", methods=["POST"])
def api_password_check():
    data = request.get_json(force=True)
    pw = data.get("password", "")
    return jsonify(password_tool.check_password_strength(pw))


@app.route("/api/vault/status", methods=["GET"])
def api_vault_status():
    return jsonify({"exists": password_tool.vault_exists()})


@app.route("/api/vault/setup", methods=["POST"])
def api_vault_setup():
    if password_tool.vault_exists():
        return jsonify({"error": "Vault already exists"}), 400
    data = request.get_json(force=True)
    master = data.get("master_password", "")
    if len(master) < 8:
        return jsonify({"error": "Master password must be at least 8 characters"}), 400
    password_tool.create_vault(master)
    return jsonify({"ok": True})


@app.route("/api/vault/unlock", methods=["POST"])
def api_vault_unlock():
    data = request.get_json(force=True)
    master = data.get("master_password", "")
    key = password_tool.unlock_vault(master)
    if key is None:
        return jsonify({"error": "Incorrect master password"}), 401
    token = os.urandom(16).hex()
    _unlocked_sessions[token] = key
    return jsonify({"token": token})


def _require_token(data):
    token = data.get("token", "")
    return _unlocked_sessions.get(token)


@app.route("/api/vault/entries", methods=["GET"])
def api_vault_list():
    return jsonify(password_tool.list_entries())


@app.route("/api/vault/entries", methods=["POST"])
def api_vault_add():
    data = request.get_json(force=True)
    key = _require_token(data)
    if key is None:
        return jsonify({"error": "Vault is locked — unlock it first"}), 401
    password_tool.add_entry(key, data.get("site", ""), data.get("username", ""), data.get("password", ""))
    return jsonify({"ok": True})


@app.route("/api/vault/entries/<int:entry_id>/reveal", methods=["POST"])
def api_vault_reveal(entry_id):
    data = request.get_json(force=True)
    key = _require_token(data)
    if key is None:
        return jsonify({"error": "Vault is locked — unlock it first"}), 401
    entry = password_tool.reveal_entry(key, entry_id)
    if entry is None:
        return jsonify({"error": "Entry not found or key mismatch"}), 404
    return jsonify(entry)


@app.route("/api/vault/entries/<int:entry_id>", methods=["DELETE"])
def api_vault_delete(entry_id):
    ok = password_tool.delete_entry(entry_id)
    return jsonify({"ok": ok})


if __name__ == "__main__":
    init_db()
    # HOST=0.0.0.0 is set inside Docker so the container port is reachable.
    # Debug mode stays off unless FLASK_DEBUG=1 (never enable it on a shared network).
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5000")),
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
    )
