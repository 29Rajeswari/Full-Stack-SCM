#/kafka/producer/producer.py
from kafka import KafkaProducer
import json
import time
import random

producer = KafkaProducer(
    bootstrap_servers='localhost:9092',
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
        producer.send('sensor_data', data)
        print(f"Sent to Kafka: {data}")
        time.sleep(10)

