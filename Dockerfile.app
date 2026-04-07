FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends docker.io ca-certificates yara gcc make musl-tools build-essential && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY backend /app/backend
COPY frontend /app/frontend

RUN pip install --no-cache-dir flask flask-cors waitress

RUN groupadd -g 998 docker || true && useradd -m appuser && usermod -aG docker appuser
USER appuser

ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "waitress", "--listen=0.0.0.0:5000", "backend.app:app"]


