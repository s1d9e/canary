FROM python:3.12-slim AS base

LABEL maintainer="s1d9e"
LABEL description="Canary - Honeypot Aggregation & Threat Correlation Platform"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY canary ./canary
RUN pip install --no-cache-dir .

RUN mkdir -p ~/.canary

RUN useradd -m -s /bin/bash canary
USER canary

ENTRYPOINT ["canary"]
CMD ["--help"]