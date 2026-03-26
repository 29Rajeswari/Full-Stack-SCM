#/kafka/consumer/consumer.py
from kafka import KafkaConsumer
from pymongo import MongoClient
import json
import os
from dotenv import load_dotenv
load_dotenv()

consumer = KafkaConsumer(
    'sensor_data',
    bootstrap_servers='localhost:9092',
    value_deserializer=lambda m: json.loads(m.decode('utf-8'))
)

MONGO_URI = os.getenv("MONGO_URI")

client = MongoClient(MONGO_URI)
db = client.iot_data
collection = db.sensor_readings

print("Kafka consumer started. Waiting for messages...")

for message in consumer:
    data = message.value
    collection.insert_one(data)
    print(f"Inserted into MongoDB: {data}")