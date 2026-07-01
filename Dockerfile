FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "-m", "heimdall.cli", "validate", "--semgrep", "test_data/semgrep-results-sample.json", "--config", "heimdall.yml", "--output", "reports/"]
