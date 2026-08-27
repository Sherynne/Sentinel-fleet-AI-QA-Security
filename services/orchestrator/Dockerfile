FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (cache layer)
COPY services/orchestrator/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all source code
COPY agents/ ./agents/
COPY report/ ./report/
COPY services/orchestrator/main.py .

# Create __init__ files
RUN touch agents/__init__.py report/__init__.py

ENV PORT=8000
EXPOSE 8000

CMD ["python", "main.py"]
