# Adversarial ML Attack Toolkit — Docker image
# Base: python:3.10-slim

FROM python:3.10-slim

# Install system dependencies needed by ART / scikit-learn / numpy
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        g++ \
        libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Create runtime directories
RUN mkdir -p models results data

# Expose Flask port
EXPOSE 5000

# Train models on first run if they don't already exist, then start the app.
# Using a shell entrypoint so we can conditionally train.
CMD ["sh", "-c", \
     "if [ ! -f models/malware_classifier.pkl ]; then echo 'Training models…'; python train_models.py; fi && python app.py"]
