FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY services/security/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY agents/ ./agents/
COPY services/security/main.py .
RUN touch agents/__init__.py
ENV PORT=8003
EXPOSE 8003
CMD ["python", "main.py"]
