# app.py
import os
from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.security import generate_password_hash, check_password_hash
from database import get_db, init_db, log_login_event

app = Flask(__name__)

# Used for Flask sessions
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-this-secret-key")

# Initialize database
init_db()


# -------------------------
# HOME
# -------------------------
@app.route("/")
def home():
    if "username" in session:
        return redirect(url_for("portfolio"))

    return redirect(url_for("login"))


# -------------------------
# REGISTER
# -------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # Check empty fields
        if not username or not password:
            return render_template(
                "register.html",
                error="Username and password are required."
            )

        # Hash password
        password_hash = generate_password_hash(password)

        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash)
            )
            conn.commit()
        except Exception:
            conn.close()
            return render_template(
                "register.html",
                error="Username already exists."
            )

        conn.close()
        return redirect(url_for("login"))

    return render_template("register.html")


# -------------------------
# LOGIN
# -------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip_address = request.remote_addr or "127.0.0.1"

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            log_login_event(username, ip_address, "SUCCESS")
            session["username"] = user["username"]
            session["user_id"] = user["id"]
            return redirect(url_for("portfolio"))
        else:
            log_login_event(username, ip_address, "FAILED")
            return render_template(
                "login.html",
                error="Authentication failed. Try again."
            )

    return render_template("login.html")


# -------------------------
# PORTFOLIO
# -------------------------
@app.route("/portfolio")
def portfolio():
    # Authentication check
    if "username" not in session:
        return render_template(
            "error.html",
            error="Authentication required. Please login first."
        )

    return render_template(
        "portfolio.html",
        username=session["username"]
    )


# -------------------------
# LOGOUT
# -------------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# -------------------------
# RUN SERVER
# -------------------------
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)



#  .\.venv\Scripts\Activate.ps1
#  python app.py for log page's

#  cd "c:\Users\Krishna Badiger\PortfolioSecurity\security-lab"
#  python app.py for lab page