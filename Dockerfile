# ---- Stage 1: build the React frontend ----
FROM node:22-slim AS frontend-build
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ---- Stage 2: backend serving the built UI ----
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend.py .
COPY --from=frontend-build /build/dist ./frontend/dist

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "backend:app", "--host", "0.0.0.0", "--port", "8000"]
