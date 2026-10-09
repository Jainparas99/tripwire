FROM python:3.12-slim

WORKDIR /app
ENV PYTHONPATH=/app/src

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY examples ./examples

RUN pip install --no-cache-dir .

CMD ["tripwire-gateway", "--host", "0.0.0.0", "--port", "8080"]
