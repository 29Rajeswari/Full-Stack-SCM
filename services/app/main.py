from fastapi import FastAPI, Request, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, RedirectResponse
from dotenv import load_dotenv
from fastapi.templating import Jinja2Templates
from pathlib import Path
from pymongo import MongoClient
from datetime import datetime
import logging
import os
import hashlib
from typing import Any, Dict, List
# Import routers from backend
from .backend import users, shipments, sensor_data  # make sure these files exist

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ----------------- ENV + MONGO -----------------
load_dotenv(dotenv_path=Path(__file__).parent / ".env")

def _clean_env_value(value: str | None) -> str | None:
    if value is None:
        return None
    return value.strip().strip('"\'')

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

MONGO_URI = _clean_env_value(os.getenv("MONGO_URI"))
MONGO_DB = _clean_env_value(os.getenv("MONGO_DB"))

# Admin credentials from env
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@scmxpert.com")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "Admin@123")

if not MONGO_URI or not MONGO_DB:
    raise RuntimeError("MONGO_URI and MONGO_DB must be set in .env file")

client = MongoClient(MONGO_URI)
db = client[MONGO_DB]

# ----------------- FASTAPI APP -----------------
app = FastAPI(title="Logistics Backend", version="1.0.0")

templates = Jinja2Templates(directory="templates")
# include backend routers
app.include_router(users.router)
app.include_router(shipments.router)
app.include_router(sensor_data.router)

# ----------------- SEED DEFAULT ADMIN -----------------
@app.on_event("startup")
async def create_default_admin():
    """Create default admin user if not exists."""
    users_collection = db["users"]
    
    # Check if admin user already exists
    existing_admin = users_collection.find_one({"role": "admin"})
    if existing_admin:
        logger.info("Admin user already exists, skipping seed.")
        return
    
    # Check if username is taken
    existing_user = users_collection.find_one({"username": ADMIN_USERNAME})
    if existing_user:
        logger.info(f"Username '{ADMIN_USERNAME}' already exists, updating role to admin.")
        users_collection.update_one(
            {"username": ADMIN_USERNAME},
            {"$set": {"role": "admin"}}
        )
        return
    
    # Create new admin user
    admin_doc = {
        "username": ADMIN_USERNAME,
        "email": ADMIN_EMAIL,
        "password": hash_password(ADMIN_PASSWORD),
        "role": "admin",
        "mfa_enabled": False,
        "created_at": datetime.utcnow(),
    }
    
    result = users_collection.insert_one(admin_doc)
    if result.inserted_id:
        logger.info(f"Default admin user created successfully!")
        logger.info(f"Username: {ADMIN_USERNAME}")
        logger.info(f"Email: {ADMIN_EMAIL}")
    else:
        logger.error("Failed to create default admin user.")

# ----------------- CORS -----------------
origins = [
    "http://127.0.0.1:5500",  # VSCode Live Server
    "http://localhost:5500",
    "http://127.0.0.1:8000",
    "http://localhost:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------- STATIC / FRONTEND MOUNT -----------------
BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR / "frontend"
STATIC_DIR = BASE_DIR / "static"

logger.info(f"Looking for frontend at: {FRONTEND_DIR}")
logger.info(f"Looking for static at:   {STATIC_DIR}")

# Serve /frontend/*.html
if FRONTEND_DIR.exists():
    app.mount(
        "/frontend",
        StaticFiles(directory=str(FRONTEND_DIR), html=True),
        name="frontend",
    )
else:
    logger.warning(f"Frontend directory not found at {FRONTEND_DIR}")

# Serve /static (images, css, js)
if STATIC_DIR.exists():
    app.mount(
        "/static",
        StaticFiles(directory=str(STATIC_DIR)),
        name="static",
    )
else:
    logger.warning(f"Static directory not found at {STATIC_DIR}")

# ----------------- SIMPLE ROUTES / SHORTCUTS -----------------
@app.get("/")
def root():
    """
    When you open http://127.0.0.1:8000/ in browser,
    redirect to the users page.
    """
    return RedirectResponse("/frontend/users.html")


@app.get("/create-shipment")
def create_shipment_page():
    """
    Shortcut: http://127.0.0.1:8000/create-shipment
    -> /frontend/createshipments.html
    """
    return RedirectResponse("/frontend/createshipments.html")


@app.get("/shipments-page")
def shipments_page():
    """
    Shortcut: http://127.0.0.1:8000/shipments-page
    -> /frontend/shipments.html
    """
    return RedirectResponse("/frontend/shipments.html")

@app.get("/live-streaming")
def live_streaming_shortcut():
    return RedirectResponse("/frontend/live_streaming.html")


@app.get("/logout-page")
def logout_page():
    """
    Shortcut: /logout-page -> /frontend/logout.html
    """
    return RedirectResponse("/frontend/logout.html")



@app.get("/ping")
def ping():
    return {"status": "ok"}


sensor_collection = db["device_data"]
@app.get("/api/live-stream")
def live_stream(limit: int = Query(50, ge=1, le=500)):
    """
    Read latest sensor records for the live_streaming.html page.

    Returns:
    {
      "records": [
        {
          "Device Id": "...",
          "Battery Level": 78.0,
          "Temp": 24.5,
          "Route From": "Chennai",
          "Route To": "Hyderabad",
          "Timestamp": "2025-12-04T12:34:56"
        },
        ...
      ]
    }
    """
    try:
        cursor = sensor_collection.find().sort("Timestamp", -1).limit(limit)

        records: List[Dict[str, Any]] = []
        for doc in cursor:
            doc.pop("_id", None)  # remove Mongo _id

            records.append({
                "Device Id": doc.get("Device_ID", ""),
                "Battery Level": doc.get("Battery_Level", ""),
                "Temp": doc.get("First_Sensor_temperature", ""),
                "Route From": doc.get("Route_From", ""),
                "Route To": doc.get("Route_To", ""),
                "Timestamp": doc.get("Timestamp", ""),
            })

        return {"records": records}
    except Exception as e:
        logger.exception(f"Error in /api/live-stream: {e}")
        raise HTTPException(status_code=500, detail="Database error while fetching")