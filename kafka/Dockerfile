# ---------- Kafka Worker Image (Producer / Consumer) ----------
FROM python:3.12-slim

WORKDIR /kafka_app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
 && rm -rf /var/lib/apt/lists/*

# Install Python libs needed by your kafka scripts
RUN pip install --no-cache-dir \
    kafka-python \
    python-dotenv \
    pymongo

# Copy only kafka folder contents
COPY ./kafka /kafka_app

# Default command (can be overridden in docker-compose)
# Here we default to consumer.py
CMD ["python", "consumer.py"]
