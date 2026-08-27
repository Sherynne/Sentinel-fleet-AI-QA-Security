FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
COPY services/qa/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY agents/ ./agents/
COPY services/qa/main.py .
RUN touch agents/__init__.py
ENV PORT=8002
EXPOSE 8002
CMD ["python", "main.py"]
