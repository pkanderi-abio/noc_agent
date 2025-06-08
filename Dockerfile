FROM python:3.9-slim
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Expose API port
EXPOSE 8000

# Default command: run FastAPI server
CMD ["uvicorn", "agent.api:app", "--host", "0.0.0.0", "--port", "8000"]