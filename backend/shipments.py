from fastapi import APIRouter, Form, HTTPException
from datetime import datetime
from backend.app import get_collections


router = APIRouter(prefix="/api/shipments", tags=["shipments"])


@router.post("/create")
def create_shipment(
    shipment_number: str = Form(...),
    container_number: str = Form(...),
    route_details: str = Form(...),
    goods_type: str = Form(...),
    expected_delivery_date: str = Form(...),
    po_number: str = Form(...),
    ndc_number: str = Form(...),
    serial_number_goods: str = Form(...),
    delivery_number: str = Form(...),
    batch_id: str = Form(...),
    shipment_description: str = Form(...),
    device: str = Form(...),
):
    cols = get_collections()
    shipments = cols["shipments"]

    # Check for duplicate shipment number
    if shipments.find_one({"shipment_number": shipment_number}):
        raise HTTPException(status_code=400, detail="Shipment number already exists")

    doc = {
        "shipment_number": shipment_number,
        "container_number": container_number,
        "route_details": route_details,
        "goods_type": goods_type,
        "expected_delivery_date": expected_delivery_date,
        "po_number": po_number,
        "ndc_number": ndc_number,
        "serial_number_goods": serial_number_goods,
        "delivery_number": delivery_number,
        "batch_id": batch_id,
        "shipment_description": shipment_description,
        "device": device,
        "created_at": datetime.utcnow().isoformat(),
    }

    shipments.insert_one(doc)
    return {"message": "Shipment created successfully", "shipment_number": shipment_number}


@router.get("/")
def list_shipments():
    cols = get_collections()
    shipments = cols["shipments"]
    items = list(shipments.find({}, {"_id": 0}))
    return {"total_shipments": len(items), "shipments": items}
