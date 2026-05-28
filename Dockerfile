# syntax=docker/dockerfile:1
FROM python:3.11-slim AS builder

WORKDIR /build

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ────────────────────────────────────────────
FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /root/.local /root/.local

ENV PATH=/root/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

COPY . .

RUN python -c "from netghost import __version__; print(f'NetGhost v{__version__}')"

ENTRYPOINT ["python", "-O", "-m", "netghost"]

LABEL org.opencontainers.image.title="NetGhost" \
      org.opencontainers.image.description="Network Security Analysis TUI" \
      org.opencontainers.image.version="0.1.0"
