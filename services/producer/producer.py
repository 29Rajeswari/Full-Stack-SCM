import os
import json
import time
import random
from kafka import KafkaProducer
from dotenv import load_dotenv

# Load .env file
load_dotenv()

# Read from environment (best practice)
bootstrap = os.getenv("KAFKA_BOOTSTRAP", "kafka:9092")

# Create Kafka producer
producer = KafkaProducer(
    bootstrap_servers=bootstrap,
    value_serializer=lambda v: json.dumps(v).encode('utf-8')
)

route = ['Newyork,USA', 'Chennai, India', 'Bengaluru, India', 'London,UK']

while True:
    routefrom = random.choice(route)
    routeto = random.choice(route)

    if routefrom != routeto:
        data = {
            "Battery_Level": round(random.uniform(2.0, 5.0), 2),
            "Device_ID": random.randint(1150, 1158),
            "First_Sensor_temperature": round(random.uniform(10, 40.0), 1),
            "Route_From": routefrom,
            "Route_To": routeto
        }

        producer.send('sensor_data', value=data)
        producer.flush()  # good for debugging

        print(f"Sent to Kafka: {data}")
        time.sleep(10)
