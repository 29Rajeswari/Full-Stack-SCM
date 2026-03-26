#/backend/users.py
from fastapi import APIRouter, Form, HTTPException, Depends, Request, status
from pydantic import EmailStr
from jose import jwt, JWTError
from typing import Optional
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timedelta
from pymongo import MongoClient
from dotenv import load_dotenv
import os
import hashlib
import random
import re
import logging
import requests

# ---------------------------
# Setup & Config
# ---------------------------
load_dotenv()
router = APIRouter()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SECRET_KEY = os.getenv("SECRET_KEY", "change-me-in-prod")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB = os.getenv("MONGO_DB")

RECAPTCHA_SECRET_KEY = os.getenv("RECAPTCHA_SECRET_KEY")

if not MONGO_URI or not MONGO_DB:
    raise RuntimeError("MONGO_URI and MONGO_DB must be set in .env file")

if not RECAPTCHA_SECRET_KEY:
    logger.warning(
        "RECAPTCHA_SECRET_KEY not set in environment. "
        "reCAPTCHA verification will be skipped (useful for local testing)."
    )

client = MongoClient(MONGO_URI)
db = client[MONGO_DB]
users_collection = db["users"]

# for forgot-password OTP
otp_store = {}

# OAuth2 password flow for Swagger "Authorize"
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


# ---------------------------
# Helper Functions
# ---------------------------

def hash_password(password: str) -> str:
    """Hash password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()


def validate_password(password: str) -> bool:
    """
    Password rules: 
    - At least 8 chars
    - At least one uppercase
    - At least one lowercase
    - At least one digit
    - At least one special char
    """
    return (
        len(password) >= 8
        and re.search(r"[A-Z]", password)
        and re.search(r"[a-z]", password)
        and re.search(r"[0-9]", password)
        and re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)
    )


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def verify_recaptcha(token: str, remoteip: Optional[str] = None) -> dict:
    """
    Verify Google reCAPTCHA token with Google's API.
    token  = value of 'g-recaptcha-response' from frontend.
    """
    if not RECAPTCHA_SECRET_KEY:
        # For local/testing: skip verification instead of failing
        logger.info("verify_recaptcha called but RECAPTCHA_SECRET_KEY is missing; skipping.")
        return {"success": True, "skipped": True}

    url = "https://www.google.com/recaptcha/api/siteverify"
    payload = {
        "secret": RECAPTCHA_SECRET_KEY,
        "response": token,
    }
    if remoteip:
        payload["remoteip"] = remoteip

    try:
        resp = requests.post(url, data=payload, timeout=5)
        return resp.json()
    except Exception as e:
        logger.exception("Error verifying reCAPTCHA")
        return {"success": False, "error-codes": ["request-failed", str(e)]}


# ---------------------------
# JWT Dependency (for protected APIs)
# ---------------------------

def get_current_user(token: str = Depends(oauth2_scheme)):
    """Decode JWT (from OAuth2 password flow) and return current user document."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: Optional[str] = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = users_collection.find_one({"username": username})
    if not user:
        raise credentials_exception
    return user


# ---------------------------
# SIGNUP  (with optional reCAPTCHA)
# ---------------------------

@router.post("/signup")
async def signup(
    request: Request,
    username: str = Form(...),
    email: EmailStr = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
):
    """
    Signup endpoint:
    - Validates reCAPTCHA from frontend form (g-recaptcha-response) when available
    - Checks password rules
    - Stores user in MongoDB
    """

    form = await request.form()
    # recaptcha token must come with name="g-recaptcha-response"
    recaptcha_token = form.get("g-recaptcha-response")

    # ---- reCAPTCHA logic (OPTIONAL) ----
    if RECAPTCHA_SECRET_KEY and recaptcha_token:
        recaptcha_result = verify_recaptcha(recaptcha_token, remoteip=request.client.host)

        if not recaptcha_result.get("success"):
            logger.warning(f"reCAPTCHA failed on signup: {recaptcha_result}")
            raise HTTPException(status_code=400, detail="reCAPTCHA verification failed.")
    else:
        logger.info(
            "Skipping reCAPTCHA for /signup "
            "(no token or RECAPTCHA_SECRET_KEY not set)."
        )

    # ---- Normal signup checks ----
    if password != confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    if not validate_password(password):
        raise HTTPException(
            status_code=400,
            detail="Weak password. Must include upper, lower, digit, special char and >= 8 chars."
        )

    existing = users_collection.find_one(
        {"$or": [{"username": username}, {"email": email}]}
    )
    if existing:
        raise HTTPException(status_code=400, detail="Username or email already exists")

    users_collection.insert_one({
        "username": username,
        "email": email,
        "password": hash_password(password),
        "created_at": datetime.utcnow(),
    })

    return {"message": f"Signup successful for {username}"}


# ---------------------------
# LOGIN (OAuth2 password flow for Swagger + Web)
# ---------------------------

@router.post("/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    OAuth2 password-flow login.
    Used by Swagger 'Authorize' dialog with username + password
    AND by web form (we send username & password as form fields).
    
    - form_data.username  -> username or email
    - form_data.password  -> password
    """

    username_or_email = form_data.username
    password = form_data.password

    # Find user by username or email
    user = users_collection.find_one(
        {"$or": [{"username": username_or_email}, {"email": username_or_email}]}
    )

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user["password"] != hash_password(password):
        raise HTTPException(status_code=401, detail="Invalid password")

    # Create JWT token (subject = username)
    token = create_access_token({"sub": user["username"]})

    return {"access_token": token, "token_type": "bearer"}


# ---------------------------
# FORGOT PASSWORD
# ---------------------------

@router.post("/forgot-password")
def forgot_password(email: EmailStr = Form(...)):
    user = users_collection.find_one({"email": email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    otp = str(random.randint(100000, 999999))
    expiry = datetime.utcnow() + timedelta(minutes=5)

    otp_store[email] = {"otp": otp, "expiry": expiry}

    # In real app, send OTP in email/SMS; here we simply return it for testing
    return {"message": f"OTP generated for {email}", "otp": otp, "valid_for_minutes": 5}


# ---------------------------
# RESET PASSWORD
# ---------------------------

@router.post("/reset-password")
def reset_password(
    email: EmailStr = Form(...),
    otp: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
):
    entry = otp_store.get(email)
    if not entry:
        raise HTTPException(status_code=400, detail="No OTP found for this email")

    if datetime.utcnow() > entry["expiry"]:
        del otp_store[email]
        raise HTTPException(status_code=400, detail="OTP expired")

    if entry["otp"] != otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    if new_password != confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    if not validate_password(new_password):
        raise HTTPException(
            status_code=400,
            detail="Weak password format for new password"
        )

    users_collection.update_one(
        {"email": email},
        {"$set": {"password": hash_password(new_password)}}
    )

    del otp_store[email]

    return {"message": "Password reset successful"}
