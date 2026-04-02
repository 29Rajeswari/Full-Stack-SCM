#consumer.py
from kafka import KafkaConsumer
from pymongo import MongoClient
import json
import os
from dotenv import load_dotenv

# Load .env (useful when running locally)
load_dotenv()

# Read Kafka bootstrap from env, default to kafka:9092 for Docker
KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP", "kafka:9092")

consumer = KafkaConsumer(
    'sensor_data',
    bootstrap_servers=KAFKA_BOOTSTRAP,
    value_deserializer=lambda m: json.loads(m.decode('utf-8'))
)

# MongoDB URI from env (can be Atlas or local)
MONGO_URI = os.getenv("MONGO_URI")
client = MongoClient(MONGO_URI)
db = client["mymongodb"]
collection = db["device_data"]

print("Kafka consumer started. Waiting for messages...")

for message in consumer:
    data = message.value
    collection.insert_one(data)
    print(f"Inserted into MongoDB: {data}")
