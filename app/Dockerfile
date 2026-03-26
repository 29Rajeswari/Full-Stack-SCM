# ---------- FastAPI App Image ----------
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# System deps (optional but useful)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
 && rm -rf /var/lib/apt/lists/*

# Copy dependency files first (if you have them)
# If you have a requirements.txt, uncomment these 2 lines
# COPY requirements.txt .
# RUN pip install --no-cache-dir -r requirements.txt

# If you DON'T have requirements.txt, install main libs directly:
RUN pip install --no-cache-dir \
    fastapi \
    uvicorn[standard] \
    pymongo \
    python-dotenv \
    kafka-python

# Copy project files
COPY . .

# Expose FastAPI port
EXPOSE 8000

# Default command
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
