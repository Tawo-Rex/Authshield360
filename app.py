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


# ============================================================
# SERVER-SIDE SESSION MANAGEMENT
# ============================================================

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

        security_event(
            "MFA_ENROLLMENT_SUCCESS",
            username=user["username"],
            role=user["role"],
            factor="TOTP_ENROLLMENT",
            status="SUCCESS"
        )

        return redirect(url_for("totp"))

    return render_template(
        "setup_2fa.html",
        username=user["username"],
        secret=user["totp_secret"],
        qr_code=qr_base64
    )


# ============================================================
# TOTP VERIFICATION
# ============================================================

@app.route("/totp", methods=["GET", "POST"])
def totp():

    username = session.get("pending_username")

    if not username:
        return redirect(url_for("login"))

    user = get_user(username)

    if user is None or not user["mfa_enabled"]:
        session.clear()
        return redirect(url_for("login"))

    authenticator = pyotp.TOTP(
        user["totp_secret"],
        interval=TOTP_INTERVAL
    )

    if request.method == "POST":
        code = request.form.get("otp", "").strip()

        if (
            code
            and code.isdigit()
            and len(code) == 6
            and authenticator.verify(code, valid_window=0)
        ):
            security_event(
                "TOTP_SUCCESS",
                username=user["username"],
                role=user["role"],
                factor="TOTP",
                status="SUCCESS"
            )

            if AUTH_MODE == 2:
                create_authenticated_session(
                    user,
                    "PASSWORD+TOTP"
                )
                return redirect(url_for("dashboard"))

            session["totp_verified"] = True
            return redirect(url_for("email_otp"))

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

    return render_template("totp.html")


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
# EMAIL OTP
# ============================================================

@app.route("/email-otp", methods=["GET", "POST"])
def email_otp():

    if AUTH_MODE != 3:
        return redirect(url_for("login"))

    if not session.get("totp_verified"):
        return redirect(url_for("login"))

    username = session.get("pending_username")

    if not username:
        return redirect(url_for("login"))

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

        create_authenticated_session(
            user,
            "PASSWORD+TOTP+EMAIL_OTP"
        )

        return redirect(url_for("dashboard"))

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
