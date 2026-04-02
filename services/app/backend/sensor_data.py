# backend/sensor_data.py

from fastapi import APIRouter, Form, Query, HTTPException
from datetime import datetime
from pymongo import MongoClient
from dotenv import load_dotenv
from typing import List, Any, Dict
import os
from pathlib import Path

load_dotenv(dotenv_path=Path(__file__).parent.parent / ".env")

def _clean_env_value(value: str | None) -> str | None:
    if value is None:
        return None
    return value.strip().strip('"\'')

router = APIRouter(
    prefix="/api/device_data",
    tags=["Sensor Data"]
)

MONGO_URI = _clean_env_value(os.getenv("MONGO_URI"))
MONGO_DB = _clean_env_value(os.getenv("MONGO_DB"))

if not MONGO_URI or not MONGO_DB:
    raise RuntimeError("MONGO_URI and MONGO_DB must be set in .env file")

client = MongoClient(MONGO_URI)
db = client[MONGO_DB]
sensor_collection = db["device_data"]



# Remove _id before sending to frontend
def _serialize_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    doc.pop("_id", None)
    return doc


@router.post("/create", summary="Create a sensor-data record")
def create_sensor_data(
    device_id: str = Form(...),
    battery_level: float = Form(...),
    first_sensor_temperature: float = Form(...),
    route_from: str = Form(...),
    route_to: str = Form(...),
    timestamp: str = Form(""),
):

    if not timestamp:
        timestamp = datetime.utcnow().isoformat()

    doc = {
        "Device_ID": device_id,
        "Battery_Level": battery_level,
        "First_Sensor_temperature": first_sensor_temperature,
        "Route_From": route_from,
        "Route_To": route_to,
        "Timestamp": timestamp,
        "created_at": datetime.utcnow(),
    }

    result = sensor_collection.insert_one(doc)

    return {
        "message": "Sensor data saved successfully",
        "sensor_mongo_id": str(result.inserted_id),
        "data": doc,
    }


@router.get("/", summary="List latest sensor-data records")
def list_sensor_data(
    limit: int = Query(50, ge=1, le=500),
):
    try:
        cursor = sensor_collection.find().sort("Timestamp", -1).limit(limit)
        docs = [_serialize_doc(d) for d in cursor]
        return docs
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {e}")

