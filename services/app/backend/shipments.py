# backend/shipments.py

from fastapi import APIRouter, Form, HTTPException, Query, Depends, Header, Request
from fastapi.security import OAuth2PasswordBearer
from pymongo import MongoClient
from datetime import datetime
from dotenv import load_dotenv
from jose import jwt, JWTError
from typing import Optional
import os
from pathlib import Path

load_dotenv(dotenv_path=Path(__file__).parent.parent / ".env")

def _clean_env_value(value: str | None) -> str | None:
    if value is None:
        return None
    return value.strip().strip('"\'')

MONGO_URI = _clean_env_value(os.getenv("MONGO_URI"))
MONGO_DB = _clean_env_value(os.getenv("MONGO_DB"))
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM")

if not MONGO_URI or not MONGO_DB:
    raise RuntimeError("MONGO_URI and MONGO_DB must be set in .env file")

client = MongoClient(MONGO_URI)
db = client[MONGO_DB]

# main collections
shipments_collection = db["shipments"]
devices_collection = db["devices"]   # same collection used in backend/Device.py
users_collection = db["users"]
revoked_tokens_collection = db["revoked_tokens"]

router = APIRouter(prefix="/api/shipments", tags=["Shipments"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")

# ---------- AUTH HELPERS ----------

async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """Get current user from JWT token."""
    error = HTTPException(
        status_code=401,
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

    # Check if token was revoked
    if revoked_tokens_collection.find_one({"token": token}):
        raise error

    user = users_collection.find_one({"username": username})
    if not user:
        raise error

    return user


def is_admin(user: dict) -> bool:
    """Check if user has admin role."""
    return user.get("role") == "admin"

# ---------- helpers ----------

def serialize_shipment(doc: dict) -> dict:
    """Convert Mongo document to a JSON-safe dict."""
    if not doc:
        return {}
    return {
        "id": str(doc.get("_id", "")),
        "shipment_number": doc.get("shipment_number", ""),
        "route_to": doc.get("route_to", ""),
        "route_from": doc.get("route_from", ""),
        "device": doc.get("device", ""),
        "po_number": doc.get("po_number", ""),
        "ndc_number": doc.get("ndc_number", ""),
        "serial_goods": doc.get("serial_goods", ""),
        "container_number": doc.get("container_number", ""),
        "goods_type": doc.get("goods_type", ""),
        "expected_delivery_date": doc.get("expected_delivery_date", ""),
        "delivery_number": doc.get("delivery_number", ""),
        "batch_id": doc.get("batch_id", ""),
        "description": doc.get("description", ""),
        "created_by": doc.get("created_by", "unknown"),
        "created_by_role": doc.get("created_by_role", "user"),
        "created_at": doc.get("created_at", "").isoformat()
        if isinstance(doc.get("created_at"), datetime) else "",
    }

# ---------- CREATE SHIPMENT ----------

@router.post("/create")
async def create_shipment(
    shipment_number: str = Form(...),
    route_to: str = Form(...),
    route_from: str = Form(...),
    device: str = Form(...),
    po_number: str = Form(...),
    ndc_number: str = Form(...),
    serial_goods: str = Form(...),
    container_number: str = Form(...),
    goods_type: str = Form(...),
    expected_delivery_date: str = Form(...),
    delivery_number: str = Form(...),
    batch_id: str = Form(...),
    description: str = Form(...),
    user: dict = Depends(get_current_user)
):
    """
    Called by createshipments.html:
    POST http://127.0.0.1:8000/api/shipments/create
    Requires authentication - stores who created the shipment.
    """

    if not shipment_number.strip():
        raise HTTPException(status_code=400, detail="Shipment number is required")

    # basic validation
    if not device.strip():
        raise HTTPException(status_code=400, detail="Device id is required")

    # Append device unique identifier to shipment number to keep them linked
    # e.g., if shipment_number="SHIP123" and device="DEV-001" -> "SHIP123-DEV-001"
    full_shipment_number = shipment_number.strip()

    now = datetime.utcnow()

    # Get user info
    username = user.get("username", "unknown")
    user_role = user.get("role", "user")

    # 1️⃣ Save into shipments collection (for shipments.html)
    shipment_doc = {
        "shipment_number": full_shipment_number,
        "route_to": route_to,
        "route_from": route_from,
        "device": device,
        "po_number": po_number,
        "ndc_number": ndc_number,
        "serial_goods": serial_goods,
        "container_number": container_number,
        "goods_type": goods_type,
        "expected_delivery_date": expected_delivery_date,
        "delivery_number": delivery_number,
        "batch_id": batch_id,
        "description": description,
        "created_by": username,
        "created_by_role": user_role,
        "created_at": now,
    }

    result = shipments_collection.insert_one(shipment_doc)
    saved = shipments_collection.find_one({"_id": result.inserted_id})

    return {
        "message": "Shipment created successfully",
        "shipment": serialize_shipment(saved)
    }

# ---------- UPDATE SHIPMENT ----------

@router.put("/update/{shipment_id}")
async def update_shipment(
    shipment_id: str,
    request: Request,
    user: dict = Depends(get_current_user)
):
    """
    PUT http://127.0.0.1:8000/api/shipments/update/{shipment_id}
    Update an existing shipment.
    
    Role-based access:
    - Admin: can update any shipment
    - User: can only update their own shipments
    
    Expects JSON body with shipment fields.
    """
    from bson import ObjectId
    
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")
    
    shipment_number = (data.get("shipment_number") or "").strip()
    route_to = data.get("route_to", "")
    route_from = data.get("route_from", "")
    device = data.get("device", "")
    po_number = data.get("po_number", "")
    ndc_number = data.get("ndc_number", "")
    serial_goods = data.get("serial_goods", "")
    container_number = data.get("container_number", "")
    goods_type = data.get("goods_type", "")
    expected_delivery_date = data.get("expected_delivery_date", "")
    delivery_number = data.get("delivery_number", "")
    batch_id = data.get("batch_id", "")
    description = data.get("description", "")
    
    if not shipment_number:
        raise HTTPException(status_code=400, detail="Shipment number is required")
    
    # Validate shipment exists
    try:
        obj_id = ObjectId(shipment_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid shipment ID")
    
    shipment_doc = shipments_collection.find_one({"_id": obj_id})
    if not shipment_doc:
        raise HTTPException(status_code=404, detail="Shipment not found")
    
    # Check permissions
    username = user.get("username", "")
    user_is_admin = is_admin(user)
    
    if not user_is_admin and shipment_doc.get("created_by") != username:
        raise HTTPException(status_code=403, detail="You don't have permission to update this shipment")
    
    # Update document
    update_data = {
        "shipment_number": shipment_number,
        "route_to": route_to,
        "route_from": route_from,
        "device": device,
        "po_number": po_number,
        "ndc_number": ndc_number,
        "serial_goods": serial_goods,
        "container_number": container_number,
        "goods_type": goods_type,
        "expected_delivery_date": expected_delivery_date,
        "delivery_number": delivery_number,
        "batch_id": batch_id,
        "description": description,
    }
    
    result = shipments_collection.update_one(
        {"_id": obj_id},
        {"$set": update_data}
    )
    
    if result.modified_count == 0:
        raise HTTPException(status_code=400, detail="Failed to update shipment")
    
    updated = shipments_collection.find_one({"_id": obj_id})
    
    return {
        "message": "Shipment updated successfully",
        "shipment": serialize_shipment(updated)
    }


# ---------- DELETE SHIPMENT ----------

@router.delete("/delete/{shipment_id}")
async def delete_shipment(
    shipment_id: str,
    user: dict = Depends(get_current_user)
):
    """
    DELETE http://127.0.0.1:8000/api/shipments/delete/{shipment_id}
    Delete a shipment.
    
    Role-based access:
    - Admin: can delete any shipment
    - User: can only delete their own shipments
    """
    from bson import ObjectId
    
    # Validate shipment exists
    try:
        obj_id = ObjectId(shipment_id)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid shipment ID")
    
    shipment_doc = shipments_collection.find_one({"_id": obj_id})
    if not shipment_doc:
        raise HTTPException(status_code=404, detail="Shipment not found")
    
    # Check permissions
    username = user.get("username", "")
    user_is_admin = is_admin(user)
    
    if not user_is_admin and shipment_doc.get("created_by") != username:
        raise HTTPException(status_code=403, detail="You don't have permission to delete this shipment")
    
    result = shipments_collection.delete_one({"_id": obj_id})
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=400, detail="Failed to delete shipment")
    
    return {
        "message": "Shipment deleted successfully"
    }


# ---------- LIST SHIPMENTS ----------

@router.get("")
async def list_shipments(
    limit: int = Query(50, ge=1, le=500),
    skip: int = Query(0, ge=0),
    user: dict = Depends(get_current_user)
):
    """
    GET http://127.0.0.1:8000/api/shipments?limit=100
    Used by shipments.html to load table data.
    
    Role-based access:
    - Admin: can see all shipments
    - User: can only see their own shipments
    """
    username = user.get("username", "")
    user_is_admin = is_admin(user)

    # Build query filter based on role
    if user_is_admin:
        # Admin sees all shipments
        query_filter = {}
    else:
        # Regular user sees only their own shipments
        query_filter = {"created_by": username}

    cursor = (
        shipments_collection
        .find(query_filter)
        .sort("created_at", -1)
        .skip(skip)
        .limit(limit)
    )

    docs = [serialize_shipment(doc) for doc in cursor]
    return docs
