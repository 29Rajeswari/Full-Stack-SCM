from fastapi import APIRouter, Form, HTTPException
from typing import Dict, Any
import hashlib
import re
from backend.app import get_collections


router = APIRouter(prefix="/api/users", tags=["users"])

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def validate_email(email: str) -> bool:
    return re.match(r"[^@]+@[^@]+\.[^@]+", email) is not None

def validate_password(password: str) -> bool:
    return (
        len(password) >= 8
        and re.search(r"[A-Z]", password)
        and re.search(r"[a-z]", password)
        and re.search(r"[0-9]", password)
        and re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)
    )

@router.post("/signup")
def signup(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
):
    username = username.strip()
    email_l = email.strip().lower()

    if not validate_email(email_l):
        raise HTTPException(status_code=400, detail="Invalid email format")
    if not validate_password(password):
        raise HTTPException(
            status_code=400,
            detail="Weak password. Requirements: >=8 chars, uppercase, lowercase, number, special char.",
        )
    if password != confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    cols = get_collections()
    users_col = cols["users"]

    # check existing username or email (case-insensitive for email)
    existing = users_col.find_one({"$or": [{"username": username}, {"email": email_l}]})
    if existing:
        raise HTTPException(status_code=400, detail="Username or email already exists")

    hashed = hash_password(password)
    users_col.insert_one({"username": username, "email": email_l, "password": hashed})

    return {"message": f"User {username} signed up successfully"}

@router.post("/login")
def login(
    identifier: str = Form(...),  # username or email
    password: str = Form(...),
):
    ident = identifier.strip()
    ident_email = ident.lower()

    cols = get_collections()
    users_col = cols["users"]

    # Try to find by username (exact) OR email (lowercased)
    user = users_col.find_one({"$or": [{"username": ident}, {"email": ident_email}]})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    stored_hash = user.get("password")
    if stored_hash != hash_password(password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # don't return password
    user_safe = {k: v for k, v in user.items() if k != "password" and k != "_id"}
    return {"message": "Login successful", "user": user_safe}
