from typing import Union

from fastapi import FastAPI

from fastapi.responses import JSONResponse
from pymongo import MongoClient
app = FastAPI()

@app.get("/hi")
def login(email:str,password:str):
    if "@" not in email:
        return {"message": "invalid email"}

@app.get("/hi")
def root():
    return {"Hello": "hi"}
client = MongoClient("mongodb://localhost:27017")  # replace with your Mongo URI
db = client["mydatabase"]  # your database name

users_collection = db["users"]
shipments_collection = db["shipments"]
devices_collection = db["device_data"]

@app.get("/")
def read_root():
    return {"message": "Connected to MongoDB successfully!"}

@app.post("/add_user")
def add_user(name: str, email: str):
    user = {"name": name, "email": email}
    users_collection.insert_one(user)
    return {"message": "User added successfully", "user": user}
