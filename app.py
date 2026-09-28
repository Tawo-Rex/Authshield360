import os
import time
import secrets
import logging
import sqlite3
import smtplib
import base64
import hashlib
from io import BytesIO
from functools import wraps
from datetime import datetime
from email.message import EmailMessage

import pyotp
import qrcode
from dotenv import load_dotenv
from flask import (
    Flask, render_template, request, redirect, url_for, session
)
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

# ============================================================
# AUTHSHIELD 360 - FINAL IMPLEMENTATION
# EduSecure Portal
# ============================================================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "CHANGE_THIS_LOCAL_SECRET_BEFORE_DEPLOYMENT"
)

# Browser session cookie settings.
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get(
    "SESSION_COOKIE_SECURE", "0"
) == "1"

# ============================================================
# AUTHENTICATION MODES
# ============================================================
# 1 = Password only
# 2 = Password + TOTP
# 3 = Password + TOTP + Email OTP

AUTH_MODE = int(os.environ.get("AUTH_MODE", "2"))

# ============================================================
# SECURITY SETTINGS
# ============================================================

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 300
SESSION_TIMEOUT = 900
TOTP_INTERVAL = 30

EMAIL_OTP_LIFETIME = 120
EMAIL_OTP_MAX_ATTEMPTS = 5

DATABASE = os.environ.get("AUTHSHIELD_DATABASE", "database.db")
LOG_DIR = "logs"
LOG_FILE = os.path.join(LOG_DIR, "security.log")

os.makedirs(LOG_DIR, exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(message)s"
)
logger = logging.getLogger("AuthShield360")

# ============================================================
# DATABASE
# ============================================================

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    db = get_db()

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            email TEXT NOT NULL,
            totp_secret TEXT NOT NULL,
            mfa_enabled INTEGER DEFAULT 0,
            failed_attempts INTEGER DEFAULT 0,
            locked_until INTEGER DEFAULT 0
        )
    """)

    # Migration for databases created by the previous version.
    columns = {
        row["name"]
        for row in db.execute("PRAGMA table_info(users)").fetchall()
    }
    if "mfa_enabled" not in columns:
        db.execute(
            "ALTER TABLE users ADD COLUMN mfa_enabled INTEGER DEFAULT 0"
        )

    db.execute("""
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            name TEXT NOT NULL,
            department TEXT NOT NULL,
            result TEXT NOT NULL
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS assignments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            course TEXT NOT NULL,
            due_date TEXT NOT NULL
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS teacher_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teacher TEXT NOT NULL,
            course TEXT NOT NULL,
            class_name TEXT NOT NULL
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS admin_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL
        )
    """)

    # Server-side authenticated-session registry.
    # A captured Flask cookie is useless after its session_id is revoked.
    db.execute("""
        CREATE TABLE IF NOT EXISTS active_sessions (
            session_id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            last_activity INTEGER NOT NULL,
            revoked INTEGER DEFAULT 0,
            auth_factor TEXT NOT NULL
        )
    """)
    # --------------------------------------------------------
    # MFA RECOVERY CODES
    # --------------------------------------------------------

    db.execute("""
        CREATE TABLE IF NOT EXISTS recovery_codes (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            username TEXT NOT NULL,

            code_hash TEXT NOT NULL,

            created_at INTEGER NOT NULL,

            used_at INTEGER DEFAULT NULL
        )
    """)

    db.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_recovery_codes_username
        ON recovery_codes(username)
    """)

    db.commit()
    create_demo_users(db)
    create_demo_data(db)
    db.close()


# ============================================================
# DEMO USERS
# ============================================================

def create_demo_users(db):
    users = [
        (
            "student1",
            "Student@123",
            "student",
            os.environ.get(
                "STUDENT_EMAIL",
                "student1@example.test"
            )
        ),
        (
            "teacher1",
            "Teacher@123",
            "teacher",
            os.environ.get(
                "TEACHER_EMAIL",
                "teacher1@example.test"
            )
        ),
        (
            "admin1",
            "Admin@123",
            "admin",
            os.environ.get(
                "ADMIN_EMAIL",
                "admin1@example.test"
            )
        )
    ]

    for username, password, role, email in users:
        existing = db.execute(
            "SELECT id FROM users WHERE username = ?",
            (username,)
        ).fetchone()

        if existing:
            # Keep existing password/TOTP/enrollment state.
            # Update only the configured test email.
            db.execute(
                "UPDATE users SET email = ? WHERE username = ?",
                (email, username)
            )
            continue

        db.execute("""
            INSERT INTO users (
                username,
                password_hash,
                role,
                email,
                totp_secret,
                mfa_enabled
            )
            VALUES (?, ?, ?, ?, ?, 0)
        """, (
            username,
            generate_password_hash(password),
            role,
            email,
            pyotp.random_base32()
        ))

    db.commit()


# ============================================================
# DEMO DATA
# ============================================================

def create_demo_data(db):
    if db.execute(
        "SELECT COUNT(*) FROM students"
    ).fetchone()[0] == 0:
        db.executemany("""
            INSERT INTO students (
                username, name, department, result
            )
            VALUES (?, ?, ?, ?)
        """, [
            (
                "student1",
                "Alex Student",
                "Computer Science",
                "A"
            ),
            (
                "student2",
                "Jordan Student",
                "Cybersecurity",
                "B+"
            )
        ])

    if db.execute(
        "SELECT COUNT(*) FROM assignments"
    ).fetchone()[0] == 0:
        db.executemany("""
            INSERT INTO assignments (
                title, course, due_date
            )
            VALUES (?, ?, ?)
        """, [
            (
                "Network Security Report",
                "Cybersecurity",
                "2026-10-05"
            ),
            (
                "Python Programming Exercise",
                "Programming",
                "2026-10-10"
            ),
            (
                "Web Application Security",
                "Cybersecurity",
                "2026-10-15"
            )
        ])

    if db.execute(
        "SELECT COUNT(*) FROM teacher_records"
    ).fetchone()[0] == 0:
        db.executemany("""
            INSERT INTO teacher_records (
                teacher, course, class_name
            )
            VALUES (?, ?, ?)
        """, [
            (
                "teacher1",
                "Cybersecurity",
                "ND Cybersecurity"
            ),
            (
                "teacher1",
                "Networking",
                "ND Networking"
            ),
            (
                "teacher1",
                "Python Programming",
                "ND Software Engineering"
            )
        ])

    if db.execute(
        "SELECT COUNT(*) FROM admin_records"
    ).fetchone()[0] == 0:
        db.executemany("""
            INSERT INTO admin_records (
                title, description
            )
            VALUES (?, ?)
        """, [
            (
                "User Management",
                "Create, modify and review portal accounts."
            ),
            (
                "Security Monitoring",
                "Review authentication and authorization events."
            ),
            (
                "System Configuration",
                "Review portal authentication configuration."
            )
        ])

    db.commit()

def hash_otp(otp):
    return hashlib.sha256(
        otp.encode("utf-8")
    ).hexdigest()


# ============================================================
# SECURITY LOGGING
# ============================================================

def security_event(
    event,
    username="-",
    role="-",
    factor="-",
    status="-",
    reason="-"
):
    message = (
        f"{event} | "
        f"time={datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
        f"ip={request.remote_addr} | "
        f"username={username} | "
        f"role={role} | "
        f"factor={factor} | "
        f"status={status} | "
        f"reason={reason}"
    )
    logger.info(message)


# ============================================================
# USER LOOKUP
# ============================================================

def get_user(username):
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    ).fetchone()
    db.close()
    return user


def get_user_by_email(email):

    db = get_db()

    user = db.execute(
        """
        SELECT *
        FROM users
        WHERE LOWER(email) = LOWER(?)
        LIMIT 1
        """,
        (email,)
    ).fetchone()

    db.close()

    return user
# ============================================================
# SERVER-SIDE SESSION MANAGEMENT
# ============================================================

# ============================================================
# MFA RECOVERY CODES
# ============================================================

def hash_recovery_code(code):
    return hashlib.sha256(
        code.encode("utf-8")
    ).hexdigest()


def generate_recovery_codes(username):
    """
    Generate a fresh set of 10 recovery codes.

    Only hashes are stored in the database.
    The plaintext codes are returned once
    so the user can save them.
    """

    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

    codes = []

    for _ in range(10):

        code = "".join(
            secrets.choice(alphabet)
            for _ in range(12)
        )

        formatted = (
            code[:4]
            + "-"
            + code[4:8]
            + "-"
            + code[8:12]
        )

        codes.append(formatted)

    db = get_db()

    # Remove any previous unused recovery codes.
    db.execute(
        """
        DELETE FROM recovery_codes
        WHERE username = ?
        """,
        (username,)
    )

    created_at = int(time.time())

    for code in codes:

        db.execute(
            """
            INSERT INTO recovery_codes
            (
                username,
                code_hash,
                created_at
            )
            VALUES (?, ?, ?)
            """,
            (
                username,
                hash_recovery_code(code),
                created_at
            )
        )

    db.commit()
    db.close()

    security_event(
        "RECOVERY_CODES_GENERATED",
        username=username,
        factor="RECOVERY_CODE",
        status="SUCCESS",
        reason="NEW_CODE_SET"
    )

    return codes


def verify_recovery_code(username, submitted_code):

    submitted_code = (
        submitted_code
        .strip()
        .upper()
    )

    code_hash = hash_recovery_code(
        submitted_code
    )

    db = get_db()

    record = db.execute(
        """
        SELECT id
        FROM recovery_codes
        WHERE username = ?
          AND code_hash = ?
          AND used_at IS NULL
        LIMIT 1
        """,
        (
            username,
            code_hash
        )
    ).fetchone()

    if record is None:

        db.close()

        return False

    db.execute(
        """
        UPDATE recovery_codes
        SET used_at = ?
        WHERE id = ?
        """,
        (
            int(time.time()),
            record["id"]
        )
    )

    db.commit()
    db.close()

    return True


def count_unused_recovery_codes(username):

    db = get_db()

    result = db.execute(
        """
        SELECT COUNT(*) AS count
        FROM recovery_codes
        WHERE username = ?
          AND used_at IS NULL
        """,
        (username,)
    ).fetchone()

    db.close()

    return result["count"]

def create_authenticated_session(user, factor):
    session.clear()

    session_id = secrets.token_urlsafe(32)
    now = int(time.time())

    db = get_db()
    db.execute("""
        INSERT INTO active_sessions (
            session_id,
            username,
            role,
            created_at,
            last_activity,
            revoked,
            auth_factor
        )
        VALUES (?, ?, ?, ?, ?, 0, ?)
    """, (
        session_id,
        user["username"],
        user["role"],
        now,
        now,
        factor
    ))
    db.commit()
    db.close()

    session["username"] = user["username"]
    session["role"] = user["role"]
    session["session_id"] = session_id
    session["last_activity"] = now

    security_event(
        "LOGIN_SUCCESS",
        username=user["username"],
        role=user["role"],
        factor=factor,
        status="SUCCESS"
    )


def revoke_session(session_id):
    if not session_id:
        return

    db = get_db()
    db.execute(
        "UPDATE active_sessions SET revoked = 1 WHERE session_id = ?",
        (session_id,)
    )
    db.commit()
    db.close()


def revoke_all_user_sessions(username):
    db = get_db()
    db.execute(
        "UPDATE active_sessions SET revoked = 1 WHERE username = ?",
        (username,)
    )
    db.commit()
    db.close()


def authenticated_session_valid():
    session_id = session.get("session_id")
    username = session.get("username")

    if not session_id or not username:
        return False

    db = get_db()
    record = db.execute("""
        SELECT *
        FROM active_sessions
        WHERE session_id = ?
          AND username = ?
          AND revoked = 0
    """, (session_id, username)).fetchone()
    db.close()

    if record is None:
        return False

    if int(time.time()) - record["last_activity"] > SESSION_TIMEOUT:
        revoke_session(session_id)
        return False

    return True


# ============================================================
# SESSION SECURITY
# ============================================================
@app.after_request
def security_headers(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.before_request
def session_security():
    if "username" not in session:
        return

    # Pending MFA sessions are not authenticated sessions yet.
    if "session_id" not in session:
        return

    if not authenticated_session_valid():
        security_event(
            "SESSION_INVALID",
            username=session.get("username"),
            role=session.get("role", "-"),
            factor="SESSION",
            status="DENIED",
            reason="REVOKED_OR_EXPIRED"
        )
        session.clear()
        return redirect(url_for("login"))

    now = int(time.time())

    db = get_db()
    db.execute("""
        UPDATE active_sessions
        SET last_activity = ?
        WHERE session_id = ?
          AND revoked = 0
    """, (now, session["session_id"]))
    db.commit()
    db.close()

    session["last_activity"] = now


# ============================================================
# AUTHENTICATION DECORATOR
# ============================================================

def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if not authenticated_session_valid():
            session.clear()
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return wrapper


# ============================================================
# ROLE AUTHORIZATION
# ============================================================

def role_required(*allowed_roles):
    def decorator(function):
        @wraps(function)
        def wrapper(*args, **kwargs):

            if not authenticated_session_valid():
                session.clear()
                return redirect(url_for("login"))

            current_user = session.get("username")
            current_role = session.get("role")

            if current_role not in allowed_roles:
                security_event(
                    "ROLE_VIOLATION",
                    username=current_user,
                    role=current_role,
                    factor="AUTHORIZATION",
                    status="DENIED",
                    reason=(
                        f"Attempted={request.path};"
                        f"RequiredRole={','.join(allowed_roles)}"
                    )
                )

                return render_template(
                    "access_denied.html",
                    attempted_path=request.path,
                    current_role=current_role,
                    required_roles=allowed_roles
                ), 403

            return function(*args, **kwargs)

        return wrapper

    return decorator


# ============================================================
# LOGIN
# ============================================================

@app.route("/", methods=["GET", "POST"])
def login():

    if request.method == "GET":
        if authenticated_session_valid():
            return redirect(url_for("dashboard"))

        return render_template(
            "login.html",
            auth_mode=AUTH_MODE
        )

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    user = get_user(username)

    # Always return the same message for unknown users and
    # invalid passwords.
    if user is None:
        security_event(
            "LOGIN_FAILURE",
            username=username,
            factor="PASSWORD",
            status="FAILED",
            reason="INVALID_CREDENTIALS"
        )
        return render_template(
            "login.html",
            error="Invalid username or password.",
            auth_mode=AUTH_MODE
        )

    now = int(time.time())

    # --------------------------------------------------------
    # LOCKOUT
    # --------------------------------------------------------

    if user["locked_until"] > now:
        security_event(
            "LOGIN_BLOCKED",
            username=user["username"],
            role=user["role"],
            factor="PASSWORD",
            status="BLOCKED",
            reason="ACCOUNT_LOCKED"
        )
        return render_template(
            "login.html",
            error="Account temporarily locked. Try again later.",
            auth_mode=AUTH_MODE
        )

    # --------------------------------------------------------
    # PASSWORD CHECK
    # --------------------------------------------------------

    if not check_password_hash(user["password_hash"], password):

        attempts = user["failed_attempts"] + 1

        db = get_db()

        if attempts >= MAX_FAILED_ATTEMPTS:
            locked_until = now + LOCKOUT_SECONDS

            db.execute("""
                UPDATE users
                SET failed_attempts = 0,
                    locked_until = ?
                WHERE username = ?
            """, (locked_until, username))
            db.commit()
            db.close()

            security_event(
                "ACCOUNT_LOCKOUT",
                username=username,
                role=user["role"],
                factor="PASSWORD",
                status="LOCKED",
                reason="MAX_FAILED_ATTEMPTS"
            )

            return render_template(
                "login.html",
                error=(
                    "Too many failed attempts. "
                    "Account temporarily locked."
                ),
                auth_mode=AUTH_MODE
            )

        db.execute("""
            UPDATE users
            SET failed_attempts = ?
            WHERE username = ?
        """, (attempts, username))
        db.commit()
        db.close()

        security_event(
            "LOGIN_FAILURE",
            username=username,
            role=user["role"],
            factor="PASSWORD",
            status="FAILED",
            reason="INVALID_PASSWORD"
        )

        return render_template(
            "login.html",
            error="Invalid username or password.",
            auth_mode=AUTH_MODE
        )

    # --------------------------------------------------------
    # PASSWORD SUCCESS
    # --------------------------------------------------------

    db = get_db()
    db.execute("""
        UPDATE users
        SET failed_attempts = 0,
            locked_until = 0
        WHERE username = ?
    """, (username,))
    db.commit()
    db.close()

    security_event(
        "PASSWORD_SUCCESS",
        username=user["username"],
        role=user["role"],
        factor="PASSWORD",
        status="SUCCESS"
    )

    if AUTH_MODE == 1:
        create_authenticated_session(user, "PASSWORD")
        return redirect(url_for("dashboard"))

    # Start a pending authentication transaction.
    # No authenticated session is created yet.
    session.clear()
    session["pending_username"] = user["username"]
    session["pending_user_id"] = user["id"]

    # MFA must be enrolled before it can be required.
    if not user["mfa_enabled"]:
        return redirect(url_for("mfa_enrollment"))

    return render_template(
        "mfa_required.html",
        username=user["username"],
        auth_mode=AUTH_MODE
    )






# ============================================================
# ACCOUNT RECOVERY
# ============================================================

@app.route(
    "/account-recovery",
    methods=["GET", "POST"]
)
def account_recovery():

    if request.method == "GET":

        return render_template(
            "account_recovery.html"
        )

    email = request.form.get(
        "email",
        ""
    ).strip().lower()

    if not email:

        return render_template(
            "account_recovery.html",
            error="Please enter your registered email address."
        )

    user = get_user_by_email(email)

    # Do not reveal whether an account exists.
    if user is None:

        security_event(
            "ACCOUNT_RECOVERY_REQUEST",
            factor="RECOVERY",
            status="FAILED",
            reason="UNREGISTERED_EMAIL"
        )

        return render_template(
            "account_recovery.html",
            message=(
                "If an account is associated with that email, "
                "a verification code has been sent."
            )
        )

    # Generate a six-digit recovery verification code.
    otp = str(
        secrets.randbelow(900000) + 100000
    )

    session.clear()

    session["recovery_email"] = email
    session["recovery_user_id"] = user["id"]
    session["recovery_otp_hash"] = hash_otp(otp)
    session["recovery_otp_created"] = int(time.time())
    session["recovery_otp_attempts"] = 0

    delivered = send_email_otp(
        user["email"],
        otp
    )

    if not delivered:

        session.clear()

        security_event(
            "ACCOUNT_RECOVERY_EMAIL_FAILURE",
            username=user["username"],
            role=user["role"],
            factor="RECOVERY_EMAIL",
            status="FAILED",
            reason="SMTP_DELIVERY_FAILED"
        )

        return render_template(
            "account_recovery.html",
            error=(
                "We could not send the verification code. "
                "Please try again."
            )
        )

    security_event(
        "ACCOUNT_RECOVERY_REQUEST",
        username=user["username"],
        role=user["role"],
        factor="RECOVERY_EMAIL",
        status="ISSUED",
        reason="VERIFICATION_CODE_SENT"
    )

    return redirect(
        url_for("account_recovery_verify")
    )

# ============================================================
# ACCOUNT RECOVERY EMAIL VERIFICATION
# ============================================================

@app.route(
    "/account-recovery/verify",
    methods=["GET", "POST"]
)
def account_recovery_verify():

    email = session.get(
        "recovery_email"
    )

    if not email:

        return redirect(
            url_for("account_recovery")
        )

    if request.method == "GET":

        return render_template(
            "account_recovery_verify.html"
        )

    entered = request.form.get(
        "otp",
        ""
    ).strip()

    created = session.get(
        "recovery_otp_created",
        0
    )

    attempts = session.get(
        "recovery_otp_attempts",
        0
    )

    # --------------------------------------------------------
    # OTP EXPIRATION
    # --------------------------------------------------------

    if time.time() - created > EMAIL_OTP_LIFETIME:

        security_event(
            "ACCOUNT_RECOVERY_FAILURE",
            factor="RECOVERY_EMAIL",
            status="FAILED",
            reason="OTP_EXPIRED"
        )

        session.clear()

        return render_template(
            "account_recovery_verify.html",
            error=(
                "Verification code expired. "
                "Please start the recovery process again."
            )
        )

    # --------------------------------------------------------
    # MAXIMUM ATTEMPTS
    # --------------------------------------------------------

    if attempts >= EMAIL_OTP_MAX_ATTEMPTS:

        security_event(
            "ACCOUNT_RECOVERY_FAILURE",
            factor="RECOVERY_EMAIL",
            status="BLOCKED",
            reason="MAX_OTP_ATTEMPTS"
        )

        session.clear()

        return redirect(
            url_for("account_recovery")
        )

    # --------------------------------------------------------
    # VERIFY CODE
    # --------------------------------------------------------

    if (
        not entered.isdigit()
        or len(entered) != 6
        or not secrets.compare_digest(
            hash_otp(entered),
            session.get(
                "recovery_otp_hash",
                ""
            )
        )
    ):

        attempts += 1

        session["recovery_otp_attempts"] = attempts

        security_event(
            "ACCOUNT_RECOVERY_FAILURE",
            factor="RECOVERY_EMAIL",
            status="FAILED",
            reason="INVALID_OTP"
        )

        return render_template(
            "account_recovery_verify.html",
            error="Invalid verification code."
        )

    # --------------------------------------------------------
    # EMAIL VERIFICATION SUCCESS
    # --------------------------------------------------------

    user = get_user_by_email(email)

    if user is None:

        session.clear()

        return redirect(
            url_for("account_recovery")
        )

    security_event(
        "ACCOUNT_RECOVERY_EMAIL_VERIFIED",
        username=user["username"],
        role=user["role"],
        factor="RECOVERY_EMAIL",
        status="SUCCESS"
    )

    # Remove the OTP itself.
    session.pop(
        "recovery_otp_hash",
        None
    )

    session.pop(
        "recovery_otp_created",
        None
    )

    session.pop(
        "recovery_otp_attempts",
        None
    )

    # Mark the recovery transaction as verified.
    session["recovery_verified"] = True
    session["recovery_username"] = user["username"]

    return redirect(
        url_for("account_recovery_options")
    )


# ============================================================
# ACCOUNT RECOVERY OPTIONS
# ============================================================

@app.route(
    "/account-recovery/options"
)
def account_recovery_options():

    if not session.get(
        "recovery_verified"
    ):

        return redirect(
            url_for("account_recovery")
        )

    username = session.get(
        "recovery_username"
    )

    if not username:

        session.clear()

        return redirect(
            url_for("account_recovery")
        )

    user = get_user(username)

    if user is None:

        session.clear()

        return redirect(
            url_for("account_recovery")
        )

    return render_template(
        "account_recovery_options.html",
        username=user["username"]
    )

# ============================================================
# ACCOUNT RECOVERY - PASSWORD RESET
# ============================================================

@app.route(
    "/account-recovery/reset-password",
    methods=["GET", "POST"]
)
def account_recovery_reset_password():

    if not session.get("recovery_verified"):
        return redirect(
            url_for("account_recovery")
        )

    username = session.get(
        "recovery_username"
    )

    if not username:
        session.clear()
        return redirect(
            url_for("account_recovery")
        )

    user = get_user(username)

    if user is None:
        session.clear()
        return redirect(
            url_for("account_recovery")
        )

    if request.method == "GET":

        return render_template(
            "account_recovery_reset_password.html",
            username=username
        )

    password = request.form.get(
        "password",
        ""
    )

    confirm_password = request.form.get(
        "confirm_password",
        ""
    )

    if len(password) < 8:

        return render_template(
            "account_recovery_reset_password.html",
            username=username,
            error="Password must be at least 8 characters."
        )

    if password != confirm_password:

        return render_template(
            "account_recovery_reset_password.html",
            username=username,
            error="Passwords do not match."
        )

    db = get_db()

    db.execute(
        """
        UPDATE users
        SET password_hash = ?,
            failed_attempts = 0,
            locked_until = 0
        WHERE username = ?
        """,
        (
            generate_password_hash(password),
            username
        )
    )

    db.commit()
    db.close()

    # Revoke all existing authenticated sessions.
    revoke_all_user_sessions(
        username
    )

    security_event(
        "PASSWORD_RESET",
        username=user["username"],
        role=user["role"],
        factor="RECOVERY_EMAIL",
        status="SUCCESS",
        reason="ACCOUNT_RECOVERY"
    )

    # Clear the recovery transaction.
    session.clear()

    return render_template(
        "account_recovery_success.html",
        message=(
            "Your password has been reset successfully. "
            "All previous sessions have been invalidated. "
            "Please log in again with your new password."
        )
    )


# ============================================================
# ACCOUNT RECOVERY - MFA RESET
# ============================================================

@app.route(
    "/account-recovery/reset-mfa",
    methods=["GET", "POST"]
)
def account_recovery_reset_mfa():

    if not session.get("recovery_verified"):
        return redirect(
            url_for("account_recovery")
        )

    username = session.get(
        "recovery_username"
    )

    if not username:
        session.clear()
        return redirect(
            url_for("account_recovery")
        )

    user = get_user(username)

    if user is None:
        session.clear()
        return redirect(
            url_for("account_recovery")
        )

    if request.method == "GET":

        return render_template(
            "account_recovery_reset_mfa.html",
            username=username
        )

    # Generate a completely new TOTP secret.
    new_secret = pyotp.random_base32()

    db = get_db()

    db.execute(
        """
        UPDATE users
        SET totp_secret = ?,
            mfa_enabled = 0
        WHERE username = ?
        """,
        (
            new_secret,
            username
        )
    )

    db.commit()
    db.close()

    # Invalidate old recovery codes.
    db = get_db()

    db.execute(
        """
        DELETE FROM recovery_codes
        WHERE username = ?
        """,
        (username,)
    )

    db.commit()
    db.close()

    # Revoke existing sessions.
    revoke_all_user_sessions(
        username
    )

    security_event(
        "MFA_METHOD_RESET",
        username=user["username"],
        role=user["role"],
        factor="TOTP",
        status="SUCCESS",
        reason="ACCOUNT_RECOVERY"
    )
    # --------------------------------------------------------
    # MFA RESET SECURITY NOTIFICATION
    # --------------------------------------------------------

    notification_sent = send_security_notification(
        user["email"],
        "AuthShield 360 - MFA Reset Notification",
        f"""
AuthShield 360 Security Notification

Hello {user["username"]},

Your multi-factor authentication (MFA) method
was RESET through the AuthShield 360 account
recovery process.

A new authenticator setup has been generated.

If you performed this action, no further action
is required.

If you did NOT perform this action, contact the
system administrator immediately.

Security event:
Action: MFA RESET
Account: {user["username"]}
Role: {user["role"]}
Reason: Account Recovery

AuthShield 360
"""
    )

    if notification_sent:

        security_event(
            "MFA_RESET_NOTIFICATION",
            username=user["username"],
            role=user["role"],
            factor="EMAIL",
            status="SUCCESS",
            reason="SMTP_DELIVERED"
        )

    else:

        security_event(
            "MFA_RESET_NOTIFICATION",
            username=user["username"],
            role=user["role"],
            factor="EMAIL",
            status="FAILED",
            reason="SMTP_DELIVERY_FAILED"
        )

    # Prepare the new authenticator QR code.
    totp = pyotp.TOTP(
        new_secret,
        interval=TOTP_INTERVAL
    )

    provisioning_uri = totp.provisioning_uri(
        name=user["email"],
        issuer_name="AuthShield 360"
    )

    qr = qrcode.make(
        provisioning_uri
    )

    buffer = BytesIO()

    qr.save(
        buffer,
        format="PNG"
    )

    qr_base64 = base64.b64encode(
        buffer.getvalue()
    ).decode("utf-8")

    # Start a new MFA enrollment transaction.
    session.clear()

    session["pending_username"] = username
    session["pending_user_id"] = user["id"]

    security_event(
        "MFA_METHOD_ADDED",
        username=user["username"],
        role=user["role"],
        factor="TOTP",
        status="ISSUED",
        reason="MFA_RESET_REENROLLMENT"
    )
    # --------------------------------------------------------
    # MFA ADDED SECURITY NOTIFICATION
    # --------------------------------------------------------

    notification_sent = send_security_notification(
        user["email"],
        "AuthShield 360 - MFA Added Notification",
        f"""
AuthShield 360 Security Notification

Hello {user["username"]},

A new multi-factor authentication (MFA) method
has been successfully added to your account.

Authentication method:
TOTP Authenticator

Account: {user["username"]}
Role: {user["role"]}

If you performed this action, no further action
is required.

If you did NOT perform this action, contact the
system administrator immediately.

AuthShield 360
"""
    )

    if notification_sent:

        security_event(
            "MFA_ADDED_NOTIFICATION",
            username=user["username"],
            role=user["role"],
            factor="EMAIL",
            status="SUCCESS",
            reason="SMTP_DELIVERED"
        )

    else:

        security_event(
            "MFA_ADDED_NOTIFICATION",
            username=user["username"],
            role=user["role"],
            factor="EMAIL",
            status="FAILED",
            reason="SMTP_DELIVERY_FAILED"
        )

    return render_template(
        "setup_2fa.html",
        username=username,
        secret=new_secret,
        qr_code=qr_base64
    )

# ============================================================
# MFA ENROLLMENT
# ============================================================

@app.route("/mfa-enrollment", methods=["GET", "POST"])
def mfa_enrollment():

    username = session.get("pending_username")

    if not username:
        return redirect(url_for("login"))

    user = get_user(username)

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    # Already enrolled: go to normal MFA verification.
    if user["mfa_enabled"]:
        return redirect(url_for("totp"))

    totp = pyotp.TOTP(
        user["totp_secret"],
        interval=TOTP_INTERVAL
    )

    provisioning_uri = totp.provisioning_uri(
        name=user["email"],
        issuer_name="AuthShield 360"
    )

    qr = qrcode.make(provisioning_uri)

    buffer = BytesIO()
    qr.save(buffer, format="PNG")
    qr_base64 = base64.b64encode(
        buffer.getvalue()
    ).decode("utf-8")

    if request.method == "POST":
        code = request.form.get("otp", "").strip()

        if not code or not code.isdigit() or len(code) != 6:
            security_event(
                "MFA_ENROLLMENT_FAILURE",
                username=user["username"],
                role=user["role"],
                factor="TOTP_ENROLLMENT",
                status="FAILED",
                reason="INVALID_FORMAT"
            )
            return render_template(
                "setup_2fa.html",
                username=user["username"],
                secret=user["totp_secret"],
                qr_code=qr_base64,
                error="Enter the six-digit code from your authenticator."
            )

        if not totp.verify(code, valid_window=0):
            security_event(
                "MFA_ENROLLMENT_FAILURE",
                username=user["username"],
                role=user["role"],
                factor="TOTP_ENROLLMENT",
                status="FAILED",
                reason="INVALID_OR_EXPIRED_OTP"
            )
            return render_template(
                "setup_2fa.html",
                username=user["username"],
                secret=user["totp_secret"],
                qr_code=qr_base64,
                error="Invalid or expired authenticator code."
            )

        db = get_db()
        db.execute("""
            UPDATE users
            SET mfa_enabled = 1
            WHERE username = ?
        """, (username,))
        db.commit()
        db.close()

        # --------------------------------------------------------
        # GENERATE MFA RECOVERY CODES
        # --------------------------------------------------------

        recovery_codes = generate_recovery_codes(
            username
        )

        security_event(
            "MFA_METHOD_ADDED",
            username=username,
            role=user["role"],
            factor="TOTP",
            status="SUCCESS",
            reason="MFA_ENROLLMENT_COMPLETED"
        )

        return render_template(
            "recovery_codes.html",
            username=username,
            recovery_codes=recovery_codes
        )
    # --------------------------------------------------------
    # DISPLAY MFA ENROLLMENT PAGE
    # --------------------------------------------------------

    return render_template(
        "setup_2fa.html",
        username=user["username"],
        secret=user["totp_secret"],
        qr_code=qr_base64
    )
# ============================================================
# RECOVERY CODE LOGIN
# ============================================================

@app.route(
    "/recovery-login",
    methods=["GET", "POST"]
)
def recovery_login():

    username = session.get(
        "pending_username"
    )

    if not username:

        return redirect(
            url_for("login")
        )

    user = get_user(
        username
    )

    if user is None:

        session.clear()

        return redirect(
            url_for("login")
        )

    if request.method == "POST":

        recovery_code = request.form.get(
            "recovery_code",
            ""
        ).strip()

        valid = verify_recovery_code(
            username,
            recovery_code
        )

        if not valid:

            security_event(
                "RECOVERY_CODE_FAILURE",
                username=user["username"],
                role=user["role"],
                factor="RECOVERY_CODE",
                status="FAILED",
                reason="INVALID_OR_USED_CODE"
            )

            return render_template(
                "recovery_login.html",
                error=(
                    "Invalid or already-used "
                    "recovery code."
                )
            )

        security_event(
            "RECOVERY_CODE_SUCCESS",
            username=user["username"],
            role=user["role"],
            factor="RECOVERY_CODE",
            status="SUCCESS"
        )

        # ----------------------------------------------------
        # SCENARIO 2
        # ----------------------------------------------------

        if AUTH_MODE == 2:

            create_authenticated_session(
                user,
                "PASSWORD+RECOVERY_CODE"
            )

            return redirect(
                url_for("dashboard")
            )

        # ----------------------------------------------------
        # SCENARIO 3
        # ----------------------------------------------------

        session["recovery_verified"] = True

        return redirect(
            url_for("email_otp")
        )

    return render_template(
        "recovery_login.html"
    )




# ============================================================
# TOTP VERIFICATION
# ============================================================

@app.route(
    "/totp",
    methods=["GET", "POST"]
)
def totp():

    username = session.get(
        "pending_username"
    )

    if not username:

        return redirect(
            url_for("login")
        )

    user = get_user(
        username
    )

    if user is None or not user["mfa_enabled"]:

        session.clear()

        return redirect(
            url_for("login")
        )

    authenticator = pyotp.TOTP(
        user["totp_secret"],
        interval=TOTP_INTERVAL
    )

    if request.method == "POST":

        print("========== TOTP DEBUG ==========")
        print("AUTH_MODE:", AUTH_MODE)
        print(
            "pending_username:",
            session.get("pending_username")
        )
        print(
            "totp_verified BEFORE:",
            session.get("totp_verified")
        )
        print("================================")

        code = request.form.get(
            "otp",
            ""
        ).strip()
        # Validate authenticator code.
        if (
            code
            and code.isdigit()
            and len(code) == 6
            and authenticator.verify(
                code,
                valid_window=0
            )
        ):

            security_event(
                "TOTP_SUCCESS",
                username=user["username"],
                role=user["role"],
                factor="TOTP",
                status="SUCCESS"
            )

            # ------------------------------------------------
            # SCENARIO 2
            # Password + TOTP
            # ------------------------------------------------

            if AUTH_MODE == 2:

                create_authenticated_session(
                    user,
                    "PASSWORD+TOTP"
                )

                return redirect(
                    url_for("dashboard")
                )

            # ------------------------------------------------
            # SCENARIO 3
            # Password + TOTP + Email OTP
            # ------------------------------------------------

            if AUTH_MODE == 3:

                session["totp_verified"] = True

                return redirect(
                    url_for("email_otp")
                )

            # ------------------------------------------------
            # Unexpected authentication mode
            # ------------------------------------------------

            security_event(
                "TOTP_FAILURE",
                username=user["username"],
                role=user["role"],
                factor="TOTP",
                status="FAILED",
                reason="INVALID_AUTH_MODE"
            )

            session.clear()

            return redirect(
                url_for("login")
            )

        # ----------------------------------------------------
        # TOTP FAILURE
        # ----------------------------------------------------

        security_event(
            "TOTP_FAILURE",
            username=user["username"],
            role=user["role"],
            factor="TOTP",
            status="FAILED",
            reason="INVALID_OR_EXPIRED_OTP"
        )

        return render_template(
            "totp.html",
            error="Invalid or expired authenticator code."
        )

    return render_template(
        "totp.html"
    )
# ============================================================
# EMAIL OTP DELIVERY
# ============================================================

def send_email_otp(
    recipient,
    otp
):

    smtp_host = os.environ.get(
        "SMTP_HOST"
    )

    smtp_port = os.environ.get(
        "SMTP_PORT"
    )

    smtp_username = os.environ.get(
        "SMTP_USERNAME"
    )

    smtp_password = os.environ.get(
        "SMTP_PASSWORD"
    )

    smtp_from = os.environ.get(
        "SMTP_FROM"
    )

    # --------------------------------------------------------
    # SMTP NOT CONFIGURED
    # --------------------------------------------------------

    if not all(
        [
            smtp_host,
            smtp_port,
            smtp_username,
            smtp_password,
            smtp_from
        ]
    ):

        logger.error(
            "EMAIL_DELIVERY_ERROR | "
            "type=SMTP_NOT_CONFIGURED"
        )

        return False

    # --------------------------------------------------------
    # EMAIL MESSAGE
    # --------------------------------------------------------

    message = EmailMessage()

    message["Subject"] = (
        "AuthShield 360 Email Verification"
    )

    message["From"] = smtp_from

    message["To"] = recipient

    message.set_content(

        f"""
AuthShield 360

Your email verification code is:

{otp}

This code expires in
{EMAIL_OTP_LIFETIME} seconds.

Do not share this code.
"""
    )

    # --------------------------------------------------------
    # SMTP DELIVERY
    # --------------------------------------------------------

    try:

        port = int(
            smtp_port
        )

        if port == 465:

            # Gmail SSL SMTP
            with smtplib.SMTP_SSL(
                smtp_host,
                port
            ) as server:

                server.login(
                    smtp_username,
                    smtp_password
                )

                server.send_message(
                    message
                )

        else:

            # STARTTLS SMTP (normally port 587)
            with smtplib.SMTP(
                smtp_host,
                port
            ) as server:

                server.ehlo()

                server.starttls()

                server.ehlo()

                server.login(
                    smtp_username,
                    smtp_password
                )

                server.send_message(
                    message
                )

        return True

    except Exception as error:

        logger.exception(
            "EMAIL_DELIVERY_ERROR | type=%s",
            type(error).__name__
        )

        return False


# ============================================================
# SECURITY NOTIFICATION EMAIL
# ============================================================

def send_security_notification(
    recipient,
    subject,
    message_body
):

    smtp_host = os.environ.get(
        "SMTP_HOST"
    )

    smtp_port = os.environ.get(
        "SMTP_PORT"
    )

    smtp_username = os.environ.get(
        "SMTP_USERNAME"
    )

    smtp_password = os.environ.get(
        "SMTP_PASSWORD"
    )

    smtp_from = os.environ.get(
        "SMTP_FROM"
    )

    # --------------------------------------------------------
    # SMTP NOT CONFIGURED
    # --------------------------------------------------------

    if not all(
        [
            smtp_host,
            smtp_port,
            smtp_username,
            smtp_password,
            smtp_from
        ]
    ):

        logger.error(
            "SECURITY_NOTIFICATION_ERROR | "
            "type=SMTP_NOT_CONFIGURED"
        )

        return False

    message = EmailMessage()

    message["Subject"] = subject

    message["From"] = smtp_from

    message["To"] = recipient

    message.set_content(
        message_body
    )

    try:

        port = int(
            smtp_port
        )

        if port == 465:

            with smtplib.SMTP_SSL(
                smtp_host,
                port
            ) as server:

                server.login(
                    smtp_username,
                    smtp_password
                )

                server.send_message(
                    message
                )

        else:

            with smtplib.SMTP(
                smtp_host,
                port
            ) as server:

                server.ehlo()

                server.starttls()

                server.ehlo()

                server.login(
                    smtp_username,
                    smtp_password
                )

                server.send_message(
                    message
                )

        return True

    except Exception as error:

        logger.exception(
            "SECURITY_NOTIFICATION_ERROR | "
            "type=%s",
            type(error).__name__
        )

        return False
# ============================================================
# EMAIL OTP
# ============================================================

@app.route(
    "/email-otp",
    methods=["GET", "POST"]
)
def email_otp():

    print("========== EMAIL OTP DEBUG ==========")
    print("METHOD:", request.method)
    print("AUTH_MODE:", AUTH_MODE)
    print("pending_username:", session.get("pending_username"))
    print("totp_verified:", session.get("totp_verified"))
    print("session_id:", session.get("session_id"))
    print("=====================================")

    if AUTH_MODE != 3:
        return redirect(
            url_for("login")
        )

    if not (
        session.get("totp_verified")
        or
        session.get("recovery_verified")
    ):

        return redirect(
            url_for("login")
        )

    username = session.get(
        "pending_username"
    )

    if not username:

        return redirect(
            url_for("login")
        )
    user = get_user(username)

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    # --------------------------------------------------------
    # ISSUE OTP ONCE PER AUTHENTICATION TRANSACTION
    # --------------------------------------------------------

    if "email_otp_hash" not in session:

        otp = str(
            secrets.randbelow(900000) + 100000
        )

        session["email_otp_hash"] = hash_otp(otp)
        session["email_otp_created"] = int(time.time())
        session["email_otp_attempts"] = 0

        delivered = send_email_otp(
            user["email"],
            otp
        )

        if not delivered:
            session.pop("email_otp_hash", None)
            session.pop("email_otp_created", None)
            session.pop("email_otp_attempts", None)

            security_event(
                "EMAIL_OTP_DELIVERY_FAILURE",
                username=user["username"],
                role=user["role"],
                factor="EMAIL_OTP",
                status="FAILED",
                reason="SMTP_DELIVERY_FAILED"
            )

            return render_template(
                "email_otp.html",
                error=(
                    "Unable to deliver the verification code. "
                    "Please try again."
                )
            )

        security_event(
            "EMAIL_OTP_ISSUED",
            username=user["username"],
            role=user["role"],
            factor="EMAIL_OTP",
            status="ISSUED",
            reason="SMTP_DELIVERED"
        )
   # --------------------------------------------------------
    # SHOW EMAIL OTP PAGE
    # --------------------------------------------------------

    if request.method == "GET":

        return render_template(
            "email_otp.html"
        )

    # --------------------------------------------------------
    # VERIFY EMAIL OTP
    # --------------------------------------------------------

    if request.method == "POST":

        entered = request.form.get("otp", "").strip()

        created = session.get(
            "email_otp_created",
            0
        )

        attempts = session.get(
            "email_otp_attempts",
            0
        )

        if time.time() - created > EMAIL_OTP_LIFETIME:
            security_event(
                "EMAIL_OTP_FAILURE",
                username=user["username"],
                role=user["role"],
                factor="EMAIL_OTP",
                status="FAILED",
                reason="OTP_EXPIRED"
            )

            session.pop("email_otp_hash", None)
            session.pop("email_otp_created", None)
            session.pop("email_otp_attempts", None)

            return render_template(
                "email_otp.html",
                error="Email verification code expired."
            )

        if attempts >= EMAIL_OTP_MAX_ATTEMPTS:
            security_event(
                "EMAIL_OTP_FAILURE",
                username=user["username"],
                role=user["role"],
                factor="EMAIL_OTP",
                status="BLOCKED",
                reason="MAX_OTP_ATTEMPTS"
            )

            session.clear()
            return redirect(url_for("login"))

        if (
            not entered.isdigit()
            or len(entered) != 6
            or not secrets.compare_digest(
                hash_otp(entered),
                session.get("email_otp_hash", "")
            )
        ):
            attempts += 1
            session["email_otp_attempts"] = attempts

            security_event(
                "EMAIL_OTP_FAILURE",
                username=user["username"],
                role=user["role"],
                factor="EMAIL_OTP",
                status="FAILED",
                reason="INVALID_OTP"
            )

            return render_template(
                "email_otp.html",
                error="Invalid email verification code."
            )

        security_event(
            "EMAIL_OTP_SUCCESS",
            username=user["username"],
            role=user["role"],
            factor="EMAIL_OTP",
            status="SUCCESS"
        )

            # Remove all pending MFA state before creating
    # the final authenticated session.

    session.pop("email_otp_hash", None)
    session.pop("email_otp_created", None)
    session.pop("email_otp_attempts", None)
    session.pop("totp_verified", None)

    if session.get("recovery_verified"):

        authentication_factor = (
            "PASSWORD+RECOVERY_CODE+EMAIL_OTP"
        )

        session.pop(
            "recovery_verified",
            None
        )

    else:

        authentication_factor = (
            "PASSWORD+TOTP+EMAIL_OTP"
        )

    create_authenticated_session(
        user,
        authentication_factor
    )

    return redirect(
        url_for("dashboard")
    )

    return render_template("email_otp.html")


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
@login_required
def dashboard():

    user = get_user(session["username"])

    return render_template(
        "dashboard.html",
        user=user,
        current_role=session["role"]
    )


# ============================================================
# STUDENT RESOURCES
# ============================================================

@app.route("/student/results")
@role_required("student")
def student_results():

    db = get_db()

    results = db.execute("""
        SELECT *
        FROM students
        WHERE username = ?
    """, (session["username"],)).fetchall()

    db.close()

    return render_template(
        "student_results.html",
        results=results
    )


@app.route("/student/assignments")
@role_required("student")
def student_assignments():

    db = get_db()

    assignments = db.execute(
        "SELECT * FROM assignments"
    ).fetchall()

    db.close()

    return render_template(
        "student_assignments.html",
        assignments=assignments
    )


# ============================================================
# RESULT MODIFICATION
# ============================================================

@app.route(
    "/results/modify/<int:result_id>",
    methods=["GET", "POST"]
)
@login_required
def modify_result(result_id):

    current_role = session.get("role")
    username = session.get("username")

    if current_role not in ["teacher", "admin"]:
        security_event(
            "ROLE_VIOLATION",
            username=username,
            role=current_role,
            factor="AUTHORIZATION",
            status="DENIED",
            reason=(
                f"Attempted=/results/modify/{result_id};"
                "RequiredRole=teacher,admin"
            )
        )

        return render_template(
            "access_denied.html",
            attempted_path=request.path,
            current_role=current_role,
            required_roles=["teacher", "admin"]
        ), 403

    db = get_db()

    result = db.execute("""
        SELECT *
        FROM students
        WHERE id = ?
    """, (result_id,)).fetchone()

    if result is None:
        db.close()
        return "Result not found", 404

    if request.method == "POST":

        new_result = request.form.get(
            "result", ""
        ).strip()

        allowed_results = {
            "A", "B+", "B", "C", "D", "F"
        }

        if new_result not in allowed_results:
            db.close()

            security_event(
                "RESULT_MODIFICATION_FAILURE",
                username=username,
                role=current_role,
                factor="AUTHORIZATION",
                status="FAILED",
                reason="INVALID_RESULT_VALUE"
            )

            return "Invalid result value.", 400

        db.execute("""
            UPDATE students
            SET result = ?
            WHERE id = ?
        """, (new_result, result_id))

        db.commit()
        db.close()

        security_event(
            "RESULT_MODIFICATION",
            username=username,
            role=current_role,
            factor="AUTHORIZATION",
            status="SUCCESS",
            reason=f"ResultID={result_id};Action=UPDATE"
        )

        return redirect(
            url_for("teacher_student_records")
        )

    db.close()

    return render_template(
        "modify_result.html",
        result=result
    )


# ============================================================
# TEACHER RESOURCES
# ============================================================

@app.route("/teacher/records")
@role_required("teacher")
def teacher_records():

    db = get_db()

    records = db.execute("""
        SELECT *
        FROM teacher_records
        WHERE teacher = ?
    """, (session["username"],)).fetchall()

    db.close()

    return render_template(
        "teacher_records.html",
        records=records
    )


@app.route("/teacher/student-records")
@role_required("teacher")
def teacher_student_records():

    db = get_db()

    records = db.execute(
        "SELECT * FROM students"
    ).fetchall()

    db.close()

    return render_template(
        "teacher_student_records.html",
        records=records
    )


@app.route("/teacher/manage-results")
@role_required("teacher", "admin")
def teacher_manage_results():

    db = get_db()

    results = db.execute(
        "SELECT * FROM students"
    ).fetchall()

    db.close()

    return render_template(
        "teacher_manage_results.html",
        results=results
    )

# ============================================================
# ADMIN - REMOVE MFA
# ============================================================

@app.route("/admin/users/<username>/remove-mfa", methods=["POST"])
@role_required("admin")
def admin_remove_mfa(username):

    admin_username = session.get("username")

    # --------------------------------------------------------
    # REQUIRE STEP-UP AUTHENTICATION
    # --------------------------------------------------------

    step_up_until = session.get(
        "step_up_verified_until",
        0
    )

    if time.time() >= step_up_until:

        session.pop(
            "step_up_verified_until",
            None
        )

        security_event(
            "STEP_UP_REQUIRED",
            username=admin_username,
            role="admin",
            factor="TOTP",
            status="REQUIRED",
            reason=f"REMOVE_MFA_TARGET={username}"
        )

        session["step_up_target"] = username

        return redirect(
            url_for("admin_step_up")
        )

    # --------------------------------------------------------
    # PREVENT ADMIN FROM REMOVING THEIR OWN MFA
    # --------------------------------------------------------

    if username == admin_username:

        security_event(
            "MFA_METHOD_REMOVAL_FAILURE",
            username=admin_username,
            role="admin",
            factor="STEP_UP_TOTP",
            status="FAILED",
            reason="SELF_MFA_REMOVAL_BLOCKED"
        )

        return "Administrators cannot remove their own MFA.", 403

    # --------------------------------------------------------
    # FIND TARGET USER
    # --------------------------------------------------------

    user = get_user(username)

    if user is None:

        return "User not found.", 404

    # --------------------------------------------------------
    # REMOVE MFA
    # --------------------------------------------------------

    db = get_db()

    db.execute(
        """
        UPDATE users
        SET mfa_enabled = 0,
            totp_secret = ?
        WHERE username = ?
        """,
        (
            pyotp.random_base32(),
            username
        )
    )

    db.execute(
        """
        DELETE FROM recovery_codes
        WHERE username = ?
        """,
        (username,)
    )

    db.commit()
    db.close()

    # Revoke all existing sessions for the affected user.
    revoke_all_user_sessions(username)

    security_event(
        "MFA_METHOD_REMOVED",
        username=username,
        role=user["role"],
        factor="STEP_UP_TOTP",
        status="SUCCESS",
        reason=f"RemovedByAdmin={admin_username}"
    )

    # --------------------------------------------------------
    # SEND SECURITY NOTIFICATION
    # --------------------------------------------------------

    send_security_notification(
        user["email"],
        "AuthShield 360 - MFA Removed",
        (
            f"Your MFA method was removed by administrator "
            f"{admin_username}. "
            f"If you did not expect this change, contact "
            f"your system administrator."
        )
    )

    security_event(
        "MFA_REMOVED_NOTIFICATION",
        username=username,
        role=user["role"],
        factor="EMAIL",
        status="SUCCESS",
        reason="MFA_REMOVAL_NOTIFICATION_SENT"
    )

    # Step-up has now been consumed.
    session.pop(
        "step_up_verified_until",
        None
    )

    session.pop(
        "step_up_target",
        None
    )

    return redirect(
        url_for("admin_users")
    )
# ============================================================
# ADMIN - STEP-UP AUTHENTICATION
# ============================================================

STEP_UP_TIMEOUT = 300


@app.route(
    "/admin/step-up",
    methods=["GET", "POST"]
)
@role_required("admin")
def admin_step_up():

    username = session.get("username")

    user = get_user(username)

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    # --------------------------------------------------------
    # SHOW STEP-UP PAGE
    # --------------------------------------------------------

    if request.method == "GET":

        return render_template(
            "admin_step_up.html",
            username=username
        )

    # --------------------------------------------------------
    # VERIFY TOTP
    # --------------------------------------------------------

    code = request.form.get(
        "otp",
        ""
    ).strip()

    authenticator = pyotp.TOTP(
        user["totp_secret"],
        interval=TOTP_INTERVAL
    )

    if (
        not code
        or not code.isdigit()
        or len(code) != 6
        or not authenticator.verify(
            code,
            valid_window=0
        )
    ):

        security_event(
            "STEP_UP_FAILURE",
            username=user["username"],
            role=user["role"],
            factor="TOTP",
            status="FAILED",
            reason="INVALID_OR_EXPIRED_OTP"
        )

        return render_template(
            "admin_step_up.html",
            username=username,
            error="Invalid or expired authenticator code."
        )

    # --------------------------------------------------------
    # STEP-UP SUCCESS
    # --------------------------------------------------------

    session["step_up_verified_until"] = (
        time.time()
        + STEP_UP_TIMEOUT
    )

    security_event(
        "STEP_UP_SUCCESS",
        username=user["username"],
        role=user["role"],
        factor="TOTP",
        status="SUCCESS",
        reason="SENSITIVE_ADMIN_FUNCTION"
    )

    return redirect(
        url_for(
            "admin_sensitive_action"
        )
    )


@app.route(
    "/admin/system/sensitive-action",
    methods=["POST"]
)
@role_required("admin")
def admin_sensitive_action():

    username = session.get("username")

    step_up_until = session.get(
        "step_up_verified_until",
        0
    )

    # --------------------------------------------------------
    # REQUIRE STEP-UP
    # --------------------------------------------------------

    if time.time() >= step_up_until:

        session.pop(
            "step_up_verified_until",
            None
        )

        security_event(
            "STEP_UP_REQUIRED",
            username=username,
            role="admin",
            factor="TOTP",
            status="REQUIRED",
            reason="SENSITIVE_ADMIN_FUNCTION"
        )

        return redirect(
            url_for("admin_step_up")
        )

    # --------------------------------------------------------
    # SENSITIVE ACTION
    # --------------------------------------------------------

    security_event(
        "SENSITIVE_ADMIN_ACTION",
        username=username,
        role="admin",
        factor="STEP_UP_TOTP",
        status="SUCCESS",
        reason="SYSTEM_CONFIGURATION_REVIEW"
    )

    return render_template(
        "admin_sensitive_success.html",
        username=username
    )


# ============================================================
# ADMIN RESOURCES
# ============================================================

@app.route("/admin/users")
@role_required("admin")
def admin_users():

    db = get_db()

    users = db.execute("""
        SELECT id, username, role, email, mfa_enabled
        FROM users
    """).fetchall()

    db.close()

    return render_template(
        "admin_users.html",
        users=users
    )


@app.route("/admin/system")
@role_required("admin")
def admin_system():

    db = get_db()

    records = db.execute(
        "SELECT * FROM admin_records"
    ).fetchall()

    db.close()

    return render_template(
        "admin_system.html",
        records=records
    )


@app.route("/admin/logs")
@role_required("admin")
def admin_logs():

    try:
        with open(
            LOG_FILE,
            "r",
            encoding="utf-8"
        ) as file:
            logs = file.readlines()
    except FileNotFoundError:
        logs = []

    return render_template(
        "admin_logs.html",
        logs=logs[-200:]
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    username = session.get("username")
    role = session.get("role")
    session_id = session.get("session_id")

    if username:
        security_event(
            "LOGOUT",
            username=username,
            role=role,
            factor="SESSION",
            status="SUCCESS"
        )

    if session_id:
        revoke_session(session_id)

    session.clear()

    return redirect(url_for("login"))


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(403)
def forbidden(error):
    return render_template(
        "access_denied.html",
        attempted_path=request.path,
        current_role=session.get("role", "-"),
        required_roles=[]
    ), 403


@app.errorhandler(500)
def internal_error(error):
    logger.exception("INTERNAL_SERVER_ERROR")
    return """
    <h1>AuthShield 360 - Internal Server Error</h1>
    <p>Check the Flask terminal for the traceback.</p>
    """, 500


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":
    init_db()

    db = get_db()
    db.execute("UPDATE active_sessions SET revoked = 1 WHERE revoked = 0")
    db.commit()
    db.close()

    print()
    print("=" * 65)
    print("                    AUTHSHIELD 360")
    print("                    EduSecure Portal")
    print("=" * 65)
    print()

    print("AUTH_MODE =", AUTH_MODE)

    if AUTH_MODE == 1:
        print("Authentication: PASSWORD ONLY")
    elif AUTH_MODE == 2:
        print("Authentication: PASSWORD + TOTP")
    elif AUTH_MODE == 3:
        print("Authentication: PASSWORD + TOTP + EMAIL OTP")
    else:
        print("WARNING: INVALID AUTH_MODE")

    print()
    print("URL: http://127.0.0.1:5000")
    print("MFA enrollment: performed after successful password")
    print("Security log:", LOG_FILE)
    print()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
