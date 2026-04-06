from fastapi import (
    APIRouter,
    Form,
    HTTPException,
    Depends,
    Request,
    status,
)
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse
from pydantic import EmailStr, BaseModel
from jose import jwt, JWTError
from typing import Optional
from datetime import datetime, timedelta
from pymongo import MongoClient
from dotenv import load_dotenv
from urllib.parse import urlencode
import os
import hashlib
import random
import re
import logging
import requests

# 🔹 NEW IMPORTS FOR EMAIL
import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path

# ---------------------------
# Setup
# ---------------------------
load_dotenv(dotenv_path=Path(__file__).parent.parent / ".env")
router = APIRouter(tags=["Users"])

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))


def _clean_env_value(value: str | None) -> str | None:
    if value is None:
        return None
    return value.strip().strip('"\'')

MONGO_URI = _clean_env_value(os.getenv("MONGO_URI"))
MONGO_DB = _clean_env_value(os.getenv("MONGO_DB"))

RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")

# Google OAuth env
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv(
    "GOOGLE_REDIRECT_URI",
    "http://127.0.0.1:8000/auth/google/callback",
)

GOOGLE_AUTH_BASE_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"
GOOGLE_TOKENINFO_URL = "https://oauth2.googleapis.com/tokeninfo"

if not MONGO_URI or not MONGO_DB:
    raise RuntimeError("MongoDB credentials missing")

client = MongoClient(MONGO_URI)
db = client[MONGO_DB]
users_collection = db["users"]
# Collection to store revoked JWTs (for logout/token invalidation)
revoked_tokens_collection = db["revoked_tokens"]
try:
    # Ensure a TTL index exists so revoked tokens are removed after expiry
    revoked_tokens_collection.create_index("expiry", expireAfterSeconds=0)
except Exception:
    logger.exception("Could not create TTL index on revoked_tokens collection")

# Store OTP temporarily (in-memory)
otp_store = {}

def generate_otp() -> str:
    """Generate a 6-digit OTP"""
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])

def send_signup_otp_email(to_email: str, otp: str):
    """Send OTP email for signup verification"""
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    from_email = os.getenv("FROM_EMAIL", smtp_user)

    if not (smtp_host and smtp_user and smtp_pass):
        logger.error("SMTP not configured properly. OTP for %s is %s", to_email, otp)
        raise RuntimeError("SMTP not configured")

    msg = EmailMessage()
    msg["Subject"] = "Your Signup Verification OTP"
    msg["From"] = from_email
    msg["To"] = to_email
    msg.set_content(
        f"""\
Dear user,

Your 6-digit OTP for account verification is: {otp}

This OTP is valid for 10 minutes.
If you did not request this, you can ignore this email.

Thank you.
"""
    )

    context = ssl.create_default_context()
    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.starttls(context=context)
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)

    logger.info("Signup OTP email sent to %s", to_email)

# OAuth2 for Swagger (Authorize button)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# ---------------------------
# Helper Functions
# ---------------------------
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()


def verify_password(raw: str, hashed: str) -> bool:
    return hash_password(raw) == hashed


def validate_password(password: str) -> bool:
    return (
        len(password) >= 8
        and re.search(r"[A-Z]", password)
        and re.search(r"[a-z]", password)
        and re.search(r"[0-9]", password)
        and re.search(r"[!@#$%^&*]", password)
    )


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_recaptcha(token: str, remoteip=None) -> dict:
    if not RECAPTCHA_SECRET_KEY:
        # If you haven't configured reCAPTCHA on backend, don't block signup
        return {"success": True}

    url = "https://www.google.com/recaptcha/api/siteverify"
    data = {"secret": RECAPTCHA_SECRET_KEY, "response": token}
    if remoteip:
        data["remoteip"] = remoteip

    try:
        return requests.post(url, data=data).json()
    except Exception as e:
        logger.error("reCAPTCHA verification error: %s", e)
        return {"success": False}


# 🔹 EMAIL SENDER FOR OTP
def send_otp_email(to_email: str, otp: str):
    smtp_host = os.getenv("SMTP_HOST")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER")
    smtp_pass = os.getenv("SMTP_PASS")
    from_email = os.getenv("FROM_EMAIL", smtp_user)

    if not (smtp_host and smtp_user and smtp_pass):
        # If SMTP is not configured, log and raise
        logger.error("SMTP not configured properly. OTP for %s is %s", to_email, otp)
        raise RuntimeError("SMTP not configured")

    msg = EmailMessage()
    msg["Subject"] = "Your Password Reset OTP"
    msg["From"] = from_email
    msg["To"] = to_email
    msg.set_content(
        f"""\
Dear user,

Your 5-digit OTP for password reset is: {otp}

This OTP is valid for 5 minutes.
If you did not request this, you can ignore this email.

Thank you.
"""
    )

    context = ssl.create_default_context()
    with smtplib.SMTP(smtp_host, smtp_port) as server:
        server.starttls(context=context)
        server.login(smtp_user, smtp_pass)
        server.send_message(msg)

    logger.info("OTP email sent to %s", to_email)


# ---------------------------
# Google ID token schema
# ---------------------------
class GoogleAuthSchema(BaseModel):
    id_token: str


# ---------------------------
# Authorization Dependency
# ---------------------------
async def get_current_user(token: str = Depends(oauth2_scheme)):
    """Used for protected APIs → Requires Bearer Token"""
    error = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise error
    except JWTError:
        raise error

    # Check if token was revoked (user logged out)
    try:
        if revoked_tokens_collection.find_one({"token": token}):
            raise error
    except Exception:
        # If the revoked tokens check fails for any reason, log and continue
        logger.exception("Error checking revoked tokens")

    user = users_collection.find_one({"username": username})
    if not user:
        raise error

    return user


# ---------------------------
# SEND OTP FOR SIGNUP
# ---------------------------
@router.post("/signup/send-otp")
async def send_signup_otp(email: EmailStr = Form(...)):
    """Send OTP to email for signup verification"""
    # Check if email already exists
    exists = users_collection.find_one({"email": email})
    if exists:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Email already registered")
    
    # Generate OTP
    otp = generate_otp()
    
    # Store OTP with timestamp (valid for 10 minutes)
    otp_store[email] = {
        "otp": otp,
        "timestamp": datetime.utcnow(),
        "expires_in": 600  # 10 minutes in seconds
    }
    
    try:
        send_signup_otp_email(email, otp)
        return {"message": "OTP sent successfully", "email": email}
    except Exception as e:
        logger.error(f"Failed to send OTP: {e}")
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Failed to send OTP email")


# ---------------------------
# VERIFY OTP FOR SIGNUP
# ---------------------------
@router.post("/signup/verify-otp")
async def verify_signup_otp(email: EmailStr = Form(...), otp: str = Form(...)):
    """Verify OTP during signup"""
    if email not in otp_store:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "OTP not found or expired. Please request a new OTP")
    
    stored_data = otp_store[email]
    stored_otp = stored_data["otp"]
    timestamp = stored_data["timestamp"]
    expires_in = stored_data["expires_in"]
    
    # Check if OTP has expired
    elapsed = (datetime.utcnow() - timestamp).total_seconds()
    if elapsed > expires_in:
        del otp_store[email]
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "OTP has expired. Please request a new OTP")
    
    # Verify OTP
    if otp != stored_otp:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid OTP")
    
    # OTP verified successfully - remove from store
    del otp_store[email]
    
    return {"message": "OTP verified successfully", "email": email, "verified": True}


# ---------------------------
# SIGNUP (with OTP verification)
# ---------------------------
@router.post("/signup")
async def signup(
    request: Request,
    first_name: str = Form(...),
    last_name: str = Form(...),
    email: EmailStr = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    otp_verified: str = Form(...),  # Must be "true" if OTP was verified
):
    form = await request.form()
    recaptcha = form.get("g-recaptcha-response")

    # Verify OTP was completed
    if otp_verified.lower() != "true":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Email verification required. Please verify your email with OTP first")

    # Optional reCAPTCHA validation
    if recaptcha:
        if not verify_recaptcha(recaptcha).get("success"):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid reCAPTCHA")

    if password != confirm_password:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Passwords do not match")

    if not validate_password(password):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Weak password — must include uppercase, lowercase, numbers, special chars",
        )

    # Generate username from first and last name
    username = f"{first_name.lower()}.{last_name.lower()}".replace(" ", "_")
    
    # Check if username or email already exists
    exists = users_collection.find_one(
        {"$or": [{"email": email}, {"username": username}]}
    )
    if exists:
        # If username exists, add a random number to make it unique
        import random
        username = f"{username}{random.randint(100, 999)}"
        exists = users_collection.find_one({"username": username})
        if exists:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Email already registered")

    users_collection.insert_one(
        {
            "username": username,
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "password": hash_password(password),
            "role": "user",
            "mfa_enabled": False,
            "created_at": datetime.utcnow(),
        }
    )

    return {"message": "Signup successful", "username": username}


# ---------------------------
# LOGIN for Swagger (OAuth2)
# ---------------------------
@router.post("/token")
async def login_swagger(form: OAuth2PasswordRequestForm = Depends()):
    user = users_collection.find_one(
        {"$or": [{"username": form.username}, {"email": form.username}]}
    )
    if not user or not verify_password(form.password, user["password"]):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid username/email or password")

    token = create_access_token({"sub": user["username"]})
    return {"access_token": token, "token_type": "bearer"}


# ---------------------------
# LOGIN for Frontend (HTML)
# ---------------------------
@router.post("/login")
async def login_frontend(
    username: str = Form(...),
    password: str = Form(...),
):
    # Step 1: validate credentials
    user = users_collection.find_one({"$or": [{"username": username}, {"email": username}]})

    if not user or not verify_password(password, user.get("password", "")):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid username/email or password")

    # If MFA enabled for this user, send a one-time OTP to their email and ask frontend to call /login/verify-otp
    if user.get("mfa_enabled"):
        otp = f"{random.randint(100000, 999999)}"  # 6-digit OTP for MFA
        otp_store[user["email"]] = {"otp": otp, "expiry": datetime.utcnow() + timedelta(minutes=5), "purpose": "mfa"}
        try:
            send_otp_email(user["email"], otp)
        except Exception:
            logger.exception("Failed to send MFA OTP")
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Failed to send MFA OTP")

        return {"mfa_required": True, "message": "MFA OTP sent to registered email"}

    # No MFA: issue token immediately
    token = create_access_token({"sub": user["username"]})
    return {
        "access_token": token,
        "token_type": "bearer",
        "role": user.get("role", "user"),
        "username": user["username"]
    }


@router.post("/login/verify-otp")
async def login_verify_otp(email: EmailStr = Form(...), otp: str = Form(...)):
    """Verify MFA OTP and issue JWT when valid."""
    record = otp_store.get(email)
    if not record or record.get("purpose") != "mfa":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "No MFA OTP found for this email")

    if datetime.utcnow() > record["expiry"]:
        otp_store.pop(email, None)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "MFA OTP expired")

    if record["otp"] != otp:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid MFA OTP")

    user = users_collection.find_one({"email": email})
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")

    # Clean up used OTP
    otp_store.pop(email, None)

    token = create_access_token({"sub": user["username"]})
    return {
        "access_token": token,
        "token_type": "bearer",
        "role": user.get("role", "user"),
        "username": user["username"]
    }


# ---------------------------
# GOOGLE SSO – ID TOKEN FLOW (used by users.html)
# ---------------------------
@router.post("/auth/google")
async def google_sso(payload: GoogleAuthSchema):
    """
    This is called by users.html:
    - Frontend sends { "id_token": "..." } from Google Identity Services
    - We verify it via Google's tokeninfo endpoint
    - Then upsert user and return our JWT
    """
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "Google OAuth is not configured on server (missing GOOGLE_CLIENT_ID).",
        )

    # Verify ID token with Google
    resp = requests.get(GOOGLE_TOKENINFO_URL, params={"id_token": payload.id_token})
    if resp.status_code != 200:
        logger.error("Google tokeninfo error: %s", resp.text)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid Google token")

    data = resp.json()

    # Make sure this token was issued for our client
    aud = data.get("aud")
    if aud != GOOGLE_CLIENT_ID:
        logger.error("Google token aud mismatch: %s != %s", aud, GOOGLE_CLIENT_ID)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid Google token (aud mismatch)")

    email = data.get("email")
    sub = data.get("sub")
    full_name = data.get("name") or (email.split("@")[0] if email else None)

    if not email:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Google did not return an email address.")

    # Find or create user
    user = users_collection.find_one({"email": email})
    if not user:
        username = full_name or email.split("@")[0]
        users_collection.insert_one(
            {
                "username": username,
                "email": email,
                "password": None,  # Google SSO user
                "created_at": datetime.utcnow(),
                "google_id": sub,
            }
        )
        user = users_collection.find_one({"email": email})

    # Issue JWT for frontend
    token = create_access_token({"sub": user["username"]})

    return {
        "access_token": token,
        "token_type": "bearer",
        "email": email,
        "username": user["username"],
    }


# ---------------------------
# GOOGLE SSO – REDIRECT FLOW (optional / legacy)
# ---------------------------
@router.get("/auth/google/login")
async def google_login():
    """
    Step 1: redirect user from frontend to Google's OAuth consent screen.
    (Legacy redirect flow – not used by current users.html)
    """
    if not GOOGLE_CLIENT_ID or not GOOGLE_REDIRECT_URI:
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "Google OAuth is not configured on server (missing GOOGLE_CLIENT_ID / GOOGLE_REDIRECT_URI).",
        )

    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent",
    }
    url = f"{GOOGLE_AUTH_BASE_URL}?{urlencode(params)}"
    return RedirectResponse(url)


@router.get("/auth/google/callback")
async def google_callback(code: Optional[str] = None, error: Optional[str] = None):
    """
    Step 2: Google redirects back here with ?code=...
    Legacy redirect flow (you can keep or remove).
    """
    if error:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Google auth error: {error}")
    if not code:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Missing authorization code")

    if not (GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and GOOGLE_REDIRECT_URI):
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "Google OAuth is not configured on server.",
        )

    # Exchange code for access_token & id_token
    data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code",
    }

    token_resp = requests.post(GOOGLE_TOKEN_URL, data=data)
    token_data = token_resp.json()
    logger.info("Google token response: %s", token_data)

    access_token = token_data.get("access_token")
    if not access_token:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Failed to obtain access token from Google.",
        )

    # Get user info from Google
    userinfo_resp = requests.get(
        GOOGLE_USERINFO_URL,
        headers={"Authorization": f"Bearer {access_token}"},
    )
    userinfo = userinfo_resp.json()
    logger.info("Google userinfo: %s", userinfo)

    email = userinfo.get("email")
    sub = userinfo.get("sub")
    full_name = userinfo.get("name") or (email.split("@")[0] if email else None)

    if not email:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Google did not return an email address.",
        )

    # Find or create local user
    user = users_collection.find_one({"email": email})
    if not user:
        username = full_name or email.split("@")[0]
        users_collection.insert_one(
            {
                "username": username,
                "email": email,
                "password": None,  # Google account; no local password yet
                "created_at": datetime.utcnow(),
                "google_id": sub,
            }
        )
        user = users_collection.find_one({"email": email})

    # Issue our own JWT
    token = create_access_token({"sub": user["username"]})

    # Redirect back to frontend, pass token in URL fragment
    redirect_url = f"/frontend/dashboard.html#token={token}"
    return RedirectResponse(redirect_url)


# ---------------------------
# FORGOT PASSWORD (5-digit OTP + REAL EMAIL)
# ---------------------------
@router.post("/forgot-password")
async def forgot_password(email: EmailStr = Form(...)):
    user = users_collection.find_one({"email": email})
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Email not registered")

    # 5-digit OTP
    otp = f"{random.randint(10000, 99999)}"
    otp_store[email] = {"otp": otp, "expiry": datetime.utcnow() + timedelta(minutes=5)}

    # Send real email
    try:
        send_otp_email(email, otp)
    except Exception as e:
        logger.error("Error sending OTP email: %s", e)
        raise HTTPException(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            "Failed to send OTP email. Please try again later.",
        )

    return {"message": "5-digit OTP sent to your email"}


# ---------------------------
# RESET PASSWORD
# ---------------------------
@router.post("/reset-password")
async def reset_password(
    email: EmailStr = Form(...),
    otp: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
):
    if email not in otp_store:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "No OTP found for this email")

    record = otp_store[email]
    if datetime.utcnow() > record["expiry"]:
        otp_store.pop(email)
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "OTP expired")

    # Validate 5-digit numeric OTP
    if len(otp) != 5 or not otp.isdigit():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid OTP format")

    if record["otp"] != otp:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid OTP")

    if new_password != confirm_password:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Passwords do not match")

    if not validate_password(new_password):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Weak password format")

    users_collection.update_one(
        {"email": email},
        {"$set": {"password": hash_password(new_password)}},
    )

    otp_store.pop(email)
    return {"message": "Password reset successful"}


# ---------------------------
# TEST PROTECTED ROUTE
# ---------------------------
@router.get("/me")
async def me(user=Depends(get_current_user)):
    return {
        "username": user["username"],
        "email": user["email"],
        "created_at": user.get("created_at"),
    }


@router.get("/account")
async def account(user=Depends(get_current_user)):
    """Compatibility endpoint used by `account.html` to fetch profile info."""
    created_at = user.get("created_at")
    if isinstance(created_at, datetime):
        created_at = created_at.isoformat()
    return {
        "username": user.get("username"),
        "email": user.get("email"),
        "created_at": created_at,
        "role": user.get("role"),
        "mfa_enabled": user.get("mfa_enabled", False),
    }


@router.post("/account/update")
async def account_update(request: Request, user=Depends(get_current_user)):
    """Update the authenticated user's username/email.
    Expects JSON: { username, email }
    """
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid JSON body")

    username = (data.get("username") or "").strip()
    email = (data.get("email") or "").strip()

    if not username or not email:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Username and email are required")

    # Check uniqueness excluding current user
    conflict = users_collection.find_one({
        "$and": [
            {"$or": [{"username": username}, {"email": email}]},
            {"username": {"$ne": user["username"]}},
        ]
    })
    if conflict:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Username or email already in use")

    users_collection.update_one({"username": user["username"]}, {"$set": {"username": username, "email": email}})
    return {"message": "Profile updated"}


@router.post("/account/change-password")
async def account_change_password(request: Request, user=Depends(get_current_user)):
    """Change password for authenticated user.
    Expects JSON: { current_password, new_password, confirm_password }
    """
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid JSON body")

    current_password = data.get("current_password") or ""
    new_password = data.get("new_password") or ""
    confirm_password = data.get("confirm_password") or ""

    if not current_password or not new_password or not confirm_password:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "All password fields are required")

    # Verify current password
    stored = users_collection.find_one({"username": user["username"]})
    if not stored or not verify_password(current_password, stored.get("password", "")):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Current password is incorrect")

    if new_password != confirm_password:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "New password and confirmation do not match")

    if not validate_password(new_password):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Weak password — must include uppercase, lowercase, numbers, special chars and be at least 8 characters")

    users_collection.update_one({"username": user["username"]}, {"$set": {"password": hash_password(new_password)}})
    return {"message": "Password updated successfully"}


# ---------------------------
# LOGOUT
# ---------------------------
@router.post("/logout")
async def logout(token: str = Depends(oauth2_scheme), user=Depends(get_current_user)):
    """
    Logout endpoint - revokes the current token by storing it in the
    `revoked_tokens` collection with its expiry. Frontend should also
    discard the token from localStorage.
    """
    # try to extract expiry from token and store the token
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        exp = payload.get("exp")
        expiry_dt = None
        if isinstance(exp, (int, float)):
            expiry_dt = datetime.utcfromtimestamp(exp)
        elif isinstance(exp, datetime):
            expiry_dt = exp

        revoked_tokens_collection.insert_one({
            "token": token,
            "expiry": expiry_dt or (datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)),
            "revoked_at": datetime.utcnow(),
        })
    except Exception as e:
        logger.exception("Failed to revoke token: %s", e)
        # Even if revocation fails, respond success so frontend can clear local token

    # Normalize created_at to ISO string if present
    created_at = user.get("created_at")
    if isinstance(created_at, datetime):
        created_at = created_at.isoformat()

    return {
        "message": "Logout successful",
        "username": user.get("username"),
        "email": user.get("email"),
        "created_at": created_at,
    }


# ---------------------------
# AUTHORIZE (Check Token Validity)
# ---------------------------
@router.get("/authorize")
async def authorize(user=Depends(get_current_user)):
    """
    Check if the current token is valid and return user information.
    Used by frontend to verify authentication status.
    """
    return {
        "authorized": True,
        "username": user["username"],
        "email": user["email"],
        "role": user.get("role", "user"),
        "created_at": user.get("created_at"),
    }


# ---------------------------
# MFA MANAGEMENT
# ---------------------------
@router.post("/mfa/enable")
async def enable_mfa(user=Depends(get_current_user)):
    users_collection.update_one({"username": user["username"]}, {"$set": {"mfa_enabled": True}})
    return {"message": "MFA enabled"}


@router.post("/mfa/disable")
async def disable_mfa(user=Depends(get_current_user)):
    users_collection.update_one({"username": user["username"]}, {"$set": {"mfa_enabled": False}})
    return {"message": "MFA disabled"}


# ---------------------------
# ADMIN PRIVILEGE REQUESTS
# ---------------------------
admin_requests = db["admin_requests"]


@router.post("/request-admin")
async def request_admin(request: Request, reason: str = Form(...), user=Depends(get_current_user)):
    """User requests admin privileges. Creates a pending request."""
    existing = admin_requests.find_one({"username": user["username"], "status": "pending"})
    if existing:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "You already have a pending admin request")

    admin_requests.insert_one({
        "username": user["username"],
        "email": user.get("email"),
        "reason": reason,
        "status": "pending",
        "requested_at": datetime.utcnow(),
    })
    return {"message": "Admin request submitted"}


def _is_admin(user):
    return user.get("role") == "admin"


@router.get("/admin/requests")
async def list_admin_requests(user=Depends(get_current_user)):
    if not _is_admin(user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin privileges required")
    docs = list(admin_requests.find().sort("requested_at", -1))
    for d in docs:
        d.pop("_id", None)
    return docs


@router.post("/admin/requests/{username}/approve")
async def approve_admin_request(username: str, user=Depends(get_current_user)):
    if not _is_admin(user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin privileges required")
    req = admin_requests.find_one({"username": username, "status": "pending"})
    if not req:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Pending request not found")
    # grant role
    users_collection.update_one({"username": username}, {"$set": {"role": "admin"}})
    admin_requests.update_one({"_id": req["_id"]}, {"$set": {"status": "approved", "processed_at": datetime.utcnow()}})
    return {"message": f"{username} granted admin role"}


@router.post("/admin/requests/{username}/reject")
async def reject_admin_request(username: str, reason: str = Form(None), user=Depends(get_current_user)):
    if not _is_admin(user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin privileges required")
    req = admin_requests.find_one({"username": username, "status": "pending"})
    if not req:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Pending request not found")
    admin_requests.update_one({"_id": req["_id"]}, {"$set": {"status": "rejected", "reason": reason, "processed_at": datetime.utcnow()}})
    return {"message": f"{username} admin request rejected"}


# ---------------------------
# USER MANAGEMENT API (for manage_users.html)
# ---------------------------
@router.get("/api/users")
async def get_all_users(user=Depends(get_current_user)):
    """Get all users - Admin only endpoint"""
    if not _is_admin(user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin privileges required")
    
    users = list(users_collection.find({}, {"password": 0}))  # Exclude password field
    
    # Convert ObjectId to string and format dates
    formatted_users = []
    for u in users:
        u["_id"] = str(u["_id"])
        if "created_at" in u and isinstance(u["created_at"], datetime):
            u["created_at"] = u["created_at"].isoformat()
        formatted_users.append(u)
    
    return formatted_users


@router.put("/api/users/{username}/role")
async def update_user_role(username: str, request: Request, user=Depends(get_current_user)):
    """Update user role - Admin only endpoint"""
    if not _is_admin(user):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Admin privileges required")
    
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Invalid JSON body")
    
    new_role = data.get("role", "").strip().lower()
    
    if new_role not in ["user", "admin"]:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Role must be 'user' or 'admin'")
    
    # Check if user exists
    target_user = users_collection.find_one({"username": username})
    if not target_user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "User not found")
    
    # Update role
    result = users_collection.update_one(
        {"username": username},
        {"$set": {"role": new_role}}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Failed to update user role")
    
    return {
        "message": f"User role updated to {new_role}",
        "username": username,
        "role": new_role
    }
