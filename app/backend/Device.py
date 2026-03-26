# backend/Device.py

from fastapi import APIRouter, Form
from datetime import datetime
from pymongo import MongoClient
from dotenv import load_dotenv
from typing import List
import os

load_dotenv()

router = APIRouter(
    prefix="/api/devices",
    tags=["Devices"]
)

MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB = os.getenv("MONGO_DB")

if not MONGO_URI or not MONGO_DB:
    raise RuntimeError("MONGO_URI and MONGO_DB must be set in .env file")

client = MongoClient(MONGO_URI)
db = client[MONGO_DB]
devices_collection = db["devices"]


@router.post("/create")
def create_device(
    device_id: str = Form(...),
    battery_level: str = Form(...),
    first_sensor_temp: str = Form(...),
    route_from: str = Form(...),
    route_to: str = Form(...),
    timestamp: str = Form(""),
):
    """
    Create a device record and store it in MongoDB.

    URL  : POST /api/devices/create
    Body : application/x-www-form-urlencoded
    """

    if not timestamp:
        timestamp = datetime.utcnow().isoformat()

    doc = {
        "device_id": device_id,
        "battery_level": battery_level,
        "first_sensor_temp": first_sensor_temp,
        "route_from": route_from,
        "route_to": route_to,
        "timestamp": timestamp,
        "created_at": datetime.utcnow(),
    }

    result = devices_collection.insert_one(doc)
    doc["_id"] = str(result.inserted_id)

    return {
        "message": "Device data saved successfully",
        "device_mongo_id": str(result.inserted_id),
        "data": doc,
    }


@router.get("/", summary="List last N device records")
def list_devices(limit: int = 10):
    """
    Check what device data is stored in Mongo.
    GET /api/devices/?limit=5
    """
    cursor = devices_collection.find().sort("created_at", -1).limit(limit)
    docs: List[dict] = []
    for d in cursor:
        d["_id"] = str(d["_id"])
        docs.append(d)
    return docs
