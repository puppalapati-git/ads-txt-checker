# Dockerfile
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# System packages (minimal) and clean up
RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App code
COPY . .

# Cloud Run provides $PORT
ENV PORT=8080

# Start with gunicorn (app module exposes "app = Flask(__name__)")
CMD exec gunicorn -b 0.0.0.0:$PORT -w 2 --threads 8 app:app
