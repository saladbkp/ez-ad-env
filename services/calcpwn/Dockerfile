FROM python:3.10-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
RUN mkdir -p /app/secrets
CMD ["gunicorn", "-b", "0.0.0.0:8081", "-w", "2", "--timeout", "30", "app:app"]
