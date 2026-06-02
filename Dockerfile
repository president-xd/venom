# syntax=docker/dockerfile:1

# =============================================================================
# VENOM | Business-Logic pentest agent
# Multi-stage build -> slim, non-root runtime image.
# =============================================================================

# ---- builder: produce a wheel with all deps -------------------------------
FROM python:3.12-slim AS builder

WORKDIR /build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1

# Copy only what's needed to build the wheel (keeps layer cache warm).
COPY pyproject.toml README.md ./
COPY venom ./venom

RUN pip install --upgrade pip build \
 && pip wheel --wheel-dir /wheels .

# ---- runtime: minimal image, drops privileges -----------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    VENOM_DATA_DIR=/data

# Non-root user — the agent should never need root.
RUN groupadd --system venom \
 && useradd --system --gid venom --home-dir /home/venom --create-home venom

WORKDIR /app

# Install the prebuilt wheel + dependencies, then discard the wheels.
COPY --from=builder /wheels /wheels
RUN pip install /wheels/*.whl && rm -rf /wheels

# Ship the example artifacts so `docker run venom run --in examples/` works.
COPY examples ./examples

# Engagement data lives on a mounted volume, writable by the venom user.
RUN mkdir -p /data /engagements && chown -R venom:venom /data /engagements /app

USER venom
VOLUME ["/data"]

# The container IS the `venom` CLI; append subcommands at `docker run`.
ENTRYPOINT ["venom"]
CMD ["--help"]
