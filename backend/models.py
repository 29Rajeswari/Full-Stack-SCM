from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime


class Signup(BaseModel):
  username: str
  email: EmailStr
  password: str
  confirm_password: str


class Shipment(BaseModel):
  shipment_number: str
  container_number: str
  route_details: str
  goods_type: str
  expected_delivery_date: str
  po_number: str
  ndc_number: str
  serial_number_goods: str
  delivery_number: str
  batch_id: str
  shipment_description: str
  device: str


class DeviceData(BaseModel):
  device_id: str
  battery_level: str
  first_sensor_temperature: str
  route_from: str
  route_to: str
  timestamp: Optional[str] = Field(default_factory=lambda: datetime.utcnow().isoformat())