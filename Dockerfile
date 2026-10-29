# ctf-harness - docker image (web UI + CLI)
#
# Build:   docker build -t ctf-harness .
# Run:     docker run -p 8787:8787 -v "$(pwd)/kb:/app/kb" -v "$(pwd)/ctfh.json:/app/ctfh.json" ctf-harness
# Compose: docker compose up -d
#
# The image keeps the full harness so the dashboard's solve subprocesses
# (which spawn ``python -m ctf_harness solve ...``) work inside the container.

FROM python:3.12-slim

# ---- system tools commonly used by CTF recipes (optional but useful) ----
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        netcat-openbsd \
        file \
        binutils \
        unzip \
        zip \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# ---- install the harness (no build isolation to keep the image small) ----
COPY pyproject.toml README.md LICENSE ./
COPY ctf_harness ./ctf_harness
RUN pip install --no-cache-dir .

# ---- runtime data directories (volume-friendly) ----
RUN mkdir -p /app/kb /app/ctfh-web-runs /root/.ctfh

# default: launch the web dashboard on 0.0.0.0 so the container is reachable
EXPOSE 8787
CMD ["ctfh", "web", "--host", "0.0.0.0", "--port", "8787"]