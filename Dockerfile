FROM python:alpine
# Install system dependencies

RUN apt-get update && apt-get install -y --no-install-recommends nmap libpcap-dev && rm -rf /var/lib/apt/lists/*

# Create working directory

WORKDIR /app

# Copy requirements and install

COPY pyproject.toml poetry.lock* /app/
RUN pip install poetry && poetry config virtualenvs.create false && poetry install --no-dev --no-interaction --no-ansi

# Copy application code

COPY . /app

# Expose ports

EXPOSE 8000

# Default command

CMD ["uvicorn", "agent.api:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]