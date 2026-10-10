FROM python:3.12-slim

# nmap  -> vulnerability scanner engine
# tshark -> Wireshark's command-line capture engine
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap tshark \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first so this layer is cached between code changes
COPY backend/requirements.txt backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

# app.py serves ../dashboard, so keep the backend/ + dashboard/ layout
COPY backend/ backend/
COPY dashboard/ dashboard/

WORKDIR /app/backend

ENV HOST=0.0.0.0 \
    PORT=5000 \
    PYTHONUNBUFFERED=1

EXPOSE 5000
CMD ["python", "app.py"]
