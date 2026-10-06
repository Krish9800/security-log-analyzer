# Stage 1: Build environment
FROM python:3.12-slim-bookworm AS builder

WORKDIR /build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libffi-dev && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --upgrade pip uv

COPY pyproject.toml README.md ./
COPY src ./src

RUN uv pip install --system --no-cache-dir .

# Stage 2: Hardened runtime environment
FROM python:3.12-slim-bookworm AS runtime

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    LOGANALYZER_ENV=production \
    LOGANALYZER_API_HOST=0.0.0.0 \
    LOGANALYZER_API_PORT=8000

# Create unprivileged security service user
RUN groupadd -g 10001 loganalyzer && \
    useradd -u 10001 -g loganalyzer -s /bin/false -M -d /app loganalyzer

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

COPY pyproject.toml README.md ./
COPY src ./src

RUN chown -R loganalyzer:loganalyzer /app

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health').read()" || exit 1

ENTRYPOINT ["uvicorn", "loganalyzer.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
