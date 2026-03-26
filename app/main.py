# main.py

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from dotenv import load_dotenv
from pathlib import Path
from pymongo import MongoClient
import logging
import os

# Import routers from backend
from backend import users, shipments, Device  # make sure these files exist

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ----------------- ENV + MONGO -----------------
load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
MONGO_DB = os.getenv("MONGO_DB")

if not MONGO_URI or not MONGO_DB:
    raise RuntimeError("MONGO_URI and MONGO_DB must be set in .env file")

client = MongoClient(MONGO_URI)
db = client[MONGO_DB]

# ----------------- FASTAPI APP -----------------
app = FastAPI(title="Logistics Backend", version="1.0.0")

# include backend routers
app.include_router(users.router)
app.include_router(shipments.router)
app.include_router(Device.router)

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
    app.mount("/frontend", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")
else:
    logger.warning(f"Frontend directory not found at {FRONTEND_DIR}")

# Serve /static (images, css, js)
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
else:
    logger.warning(f"Static directory not found at {STATIC_DIR}")

# ----------------- SIMPLE ROUTES / SHORTCUTS -----------------

@app.get("/")
def root():
    """
    When you open http://127.0.0.1:8000/ in browser,
    redirect to the shipments list page.
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
    Shortcut: http://127.0.0.1:8000/users-page
    -> /frontend/users.html
    """
    return RedirectResponse("/frontend/users.html")

@app.get("/ping")
def ping():
    return {"status": "ok"}