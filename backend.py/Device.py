from fastapi import APIRouter, Form, HTTPException
from datetime import datetime
from backend.app import get_collections


router = APIRouter(prefix="/api/device", tags=["device"])


@router.post("/add")
def add_device_data(
    device_id: str = Form(...),
    battery_level: str = Form(...),
    first_sensor_temperature: str = Form(...),
    route_from: str = Form(...),
    route_to: str = Form(...),
    timestamp: str = Form(default_factory=lambda: datetime.utcnow().isoformat()),
):
    cols = get_collections()
    device_data = cols["device_data"]

    doc = {
        "device_id": device_id,
        "battery_level": battery_level,
        "first_sensor_temperature": first_sensor_temperature,
        "route_from": route_from,
        "route_to": route_to,
        "timestamp": timestamp,
        "created_at": datetime.utcnow().isoformat(),
    }

    device_data.insert_one(doc)
    return {"message": f"Device data stored for {device_id}"}


@router.get("/records/{device_id}")
def get_device_data(device_id: str):
    cols = get_collections()
    device_data = cols["device_data"]
    data = list(device_data.find({"device_id": device_id}, {"_id": 0}))

    if not data:
        raise HTTPException(status_code=404, detail="No data found for this device")
    return {"device_id": device_id, "records": data}