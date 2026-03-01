"""
=============================================================
  Ethical Hacking Lab - Login Security Testing Platform
  Built with Flask for educational purposes

  RAMA: sin-lockout
  Sin límite de intentos — vulnerable a fuerza bruta (Hydra)
=============================================================
"""

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from datetime import datetime
import hashlib
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# ──────────────────────────────────────────────
# "DATABASE"
# ──────────────────────────────────────────────
USERS_DB = {
    "admin": {
        "password_hash": hashlib.sha256("secretpass123".encode()).hexdigest(),
        "role": "admin"
    },
    "usuario1": {
        "password_hash": hashlib.sha256("password456".encode()).hexdigest(),
        "role": "user"
    }
}

# Global stores
attack_logs = []


# ──────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def log_attempt(ip, username, password, success):
    """Log every attempt for the admin panel."""
    attack_logs.append({
        "id": len(attack_logs) + 1,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "ip_address": ip,
        "username": username,
        "password_tried": password,
        "success": success,
        "user_agent": request.headers.get("User-Agent", "Unknown")
    })


# ──────────────────────────────────────────────
# ROUTES
# ──────────────────────────────────────────────

@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip = request.remote_addr

        auth_success = False
        if username in USERS_DB:
            if USERS_DB[username]["password_hash"] == hash_password(password):
                auth_success = True

        if auth_success:
            log_attempt(ip, username, "****", True)
            session["user"] = username
            session["role"] = USERS_DB[username]["role"]
            return redirect(url_for("dashboard"))

        log_attempt(ip, username, password, False)
        error = "Credenciales incorrectas"

    return render_template("login.html", error=error, locked=False, remaining=0)


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html",
                           username=session["user"],
                           role=session.get("role", "user"))


@app.route("/logs")
def logs():
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))

    stats = {
        "total_attempts": len(attack_logs),
        "failed_attempts": sum(1 for l in attack_logs if not l["success"]),
        "successful_attempts": sum(1 for l in attack_logs if l["success"]),
        "unique_ips": len(set(l["ip_address"] for l in attack_logs)) if attack_logs else 0,
        "locked_accounts": 0
    }

    return render_template("logs.html", logs=reversed(attack_logs), stats=stats)


@app.route("/api/logs")
def api_logs():
    return jsonify({"total": len(attack_logs), "logs": attack_logs[-50:]})


@app.route("/api/status")
def api_status():
    return jsonify({"status": "running", "users_count": len(USERS_DB)})


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/reset-logs", methods=["POST"])
def reset_logs():
    if "user" not in session or session.get("role") != "admin":
        return redirect(url_for("login"))
    attack_logs.clear()
    return redirect(url_for("logs"))


# ──────────────────────────────────────────────
# RUN
# ──────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "=" * 55)
    print("  ETHICAL HACKING LAB - Login Security Platform")
    print("  RAMA: sin-lockout (vulnerable a fuerza bruta)")
    print("=" * 55)
    print(f"  URL:        http://127.0.0.1:5000")
    print(f"  Admin:      admin / secretpass123")
    print(f"  Usuario:    usuario1 / password456")
    print(f"  Logs:       http://127.0.0.1:5000/logs")
    print(f"  API Logs:   http://127.0.0.1:5000/api/logs")
    print(f"  Bloqueo:    DESACTIVADO")
    print("=" * 55 + "\n")

    app.run(debug=True, host="0.0.0.0", port=5000)
