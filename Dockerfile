# Stage 1: Build virtual environment and install mcp-guard
FROM python:3.12-slim AS builder

WORKDIR /build

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY pyproject.toml README.md LICENSE ./
COPY config/ ./config/
COPY src/ ./src/
COPY demo/ ./demo/

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir .


# Stage 2: Minimal non-root runtime image
FROM python:3.12-slim AS runtime

WORKDIR /app

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUTF8=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --system mcpguard \
    && useradd --system --gid mcpguard --create-home mcpguard

COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /build/config ./config
COPY --from=builder /build/demo ./demo

RUN mkdir -p /home/mcpguard/.mcp-guard \
    && chown -R mcpguard:mcpguard /app /home/mcpguard

USER mcpguard

ENTRYPOINT ["mcp-guard"]
CMD ["--help"]
