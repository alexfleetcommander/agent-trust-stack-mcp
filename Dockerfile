FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

RUN pip install --no-cache-dir .

EXPOSE 8000

ENTRYPOINT ["agent-trust-stack-mcp"]
