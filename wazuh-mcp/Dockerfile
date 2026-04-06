FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml ./
COPY src/ src/
COPY config.toml ./

RUN pip install --no-cache-dir .

RUN useradd -r -u 1000 appuser
USER appuser

CMD ["python", "-m", "wazuh_mcp"]
