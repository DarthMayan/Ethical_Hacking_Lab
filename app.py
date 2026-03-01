"""
=============================================================
  Ethical Hacking Lab - Login Security Testing Platform
  Built with Flask for educational purposes
=============================================================
"""

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from datetime import datetime, timedelta
import hashlib
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 300  # 5 minutes

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
# Key = IP address (tracks by IP so attacker can't bypass by switching usernames)
# Value = {"count": int, "locked_until": datetime or None}
failed_attempts = {}


# ──────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def get_lockout_info(ip):
    """Returns (is_locked, seconds_remaining, attempt_count)"""
    if ip not in failed_attempts:
        failed_attempts[ip] = {"count": 0, "locked_until": None}

    info = failed_attempts[ip]

    # Check if currently locked
    if info["locked_until"] is not None:
        now = datetime.now()
        if now < info["locked_until"]:
            remaining = (info["locked_until"] - now).total_seconds()
            return True, int(remaining), info["count"]
        else:
            # Lockout expired, reset everything
            info["count"] = 0
            info["locked_until"] = None

    return False, 0, info["count"]


def add_failed_attempt(ip):
    """Increment failed count. Lock if >= MAX_ATTEMPTS. Returns new count."""
    if ip not in failed_attempts:
        failed_attempts[ip] = {"count": 0, "locked_until": None}

    failed_attempts[ip]["count"] += 1
    count = failed_attempts[ip]["count"]

    if count >= MAX_ATTEMPTS:
        failed_attempts[ip]["locked_until"] = datetime.now() + timedelta(seconds=LOCKOUT_SECONDS)

    return count


def reset_attempts(ip):
    """Reset on successful login."""
    failed_attempts[ip] = {"count": 0, "locked_until": None}


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
    locked = False
    remaining = 0

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip = request.remote_addr

        # 1) CHECK IF LOCKED
        locked, remaining, count = get_lockout_info(ip)
        if locked:
            log_attempt(ip, username, password, False)
            error = f"🔒 BLOQUEADO. Espera {remaining}s para reintentar."
            return render_template("login.html", error=error, locked=True, remaining=remaining)

        # 2) TRY TO AUTHENTICATE
        auth_success = False
        if username in USERS_DB:
            if USERS_DB[username]["password_hash"] == hash_password(password):
                auth_success = True

        if auth_success:
            log_attempt(ip, username, "****", True)
            reset_attempts(ip)
            session["user"] = username
            session["role"] = USERS_DB[username]["role"]
            return redirect(url_for("dashboard"))

        # 3) FAILED - increment counter
        log_attempt(ip, username, password, False)
        new_count = add_failed_attempt(ip)
        attempts_left = MAX_ATTEMPTS - new_count

        if attempts_left <= 0:
            _, remaining, _ = get_lockout_info(ip)
            error = f"🔒 BLOQUEADO tras {MAX_ATTEMPTS} intentos fallidos. Espera {remaining}s."
            locked = True
        else:
            error = f"❌ Credenciales incorrectas. Intentos restantes: {attempts_left}"

    return render_template("login.html", error=error, locked=locked, remaining=remaining)


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
        "locked_accounts": sum(1 for v in failed_attempts.values()
                               if v["locked_until"] and datetime.now() < v["locked_until"])
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
    failed_attempts.clear()
    return redirect(url_for("logs"))


# ──────────────────────────────────────────────
# RUN
# ──────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "=" * 55)
    print("  🔐 ETHICAL HACKING LAB - Login Security Platform")
    print("=" * 55)
    print(f"  🌐 URL:        http://127.0.0.1:5000")
    print(f"  👤 Admin:      admin / secretpass123")
    print(f"  👤 Usuario:    usuario1 / password456")
    print(f"  📊 Logs:       http://127.0.0.1:5000/logs")
    print(f"  🔌 API Logs:   http://127.0.0.1:5000/api/logs")
    print(f"  🔒 Bloqueo:    Después de {MAX_ATTEMPTS} intentos")
    print("=" * 55 + "\n")

    app.run(debug=True, host="0.0.0.0", port=5000)
