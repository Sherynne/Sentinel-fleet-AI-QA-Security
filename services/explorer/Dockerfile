FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY services/explorer/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY agents/ ./agents/
COPY services/explorer/main.py .
RUN touch agents/__init__.py
ENV PORT=8001
EXPOSE 8001
CMD ["python", "main.py"]
