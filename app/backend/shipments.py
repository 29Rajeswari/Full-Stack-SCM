# backend/shipments.py

from fastapi import APIRouter, Form, HTTPException, Query
from pymongo import MongoClient
from datetime import datetime
from dotenv import load_dotenv
from typing import List, Optional
import os

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB = os.getenv("MONGO_DB")

if not MONGO_URI or not MONGO_DB:
    raise RuntimeError("MONGO_URI and MONGO_DB must be set in .env file")

client = MongoClient(MONGO_URI)
db = client[MONGO_DB]
shipments_collection = db["shipments"]

router = APIRouter(prefix="/api/shipments", tags=["Shipments"])

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
        "created_at": doc.get("created_at", "").isoformat() if isinstance(doc.get("created_at"), datetime) else "",
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
    description: str = Form(...)
):
    """
    This endpoint is called by createshipments.html via:
    POST http://127.0.0.1:8000/api/shipments/create
    with form data (application/x-www-form-urlencoded).
    """

    # optional: simple validation checks
    if not shipment_number.strip():
        raise HTTPException(status_code=400, detail="Shipment number is required")

    doc = {
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
        "created_at": datetime.utcnow(),
    }

    result = shipments_collection.insert_one(doc)
    saved = shipments_collection.find_one({"_id": result.inserted_id})

    return {
        "message": "Shipment created successfully",
        "data": serialize_shipment(saved),
    }

# ---------- LIST SHIPMENTS ----------

@router.get("")
async def list_shipments(
    limit: int = Query(50, ge=1, le=500),
    skip: int = Query(0, ge=0)
):
    """
    GET http://127.0.0.1:8000/api/shipments?limit=100
    Used by shipments.html to load table data.
    """
    cursor = (
        shipments_collection
        .find({})
        .sort("created_at", -1)
        .skip(skip)
        .limit(limit)
    )

    docs = [serialize_shipment(doc) for doc in cursor]
    return docs
