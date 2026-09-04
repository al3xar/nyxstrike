# NyxStrike — Kali Linux rolling base image
FROM kalilinux/kali-rolling:latest

# Avoid interactive prompts during package install
ENV DEBIAN_FRONTEND=noninteractive

# ── System basics + build deps ─────────────────────────────────────────────────
RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gcc \
    git \
    python3 \
    python3-dev \
    python3-pip \
    python3-venv \
    sudo \
    wget \
 && rm -rf /var/lib/apt/lists/*

# ── Install uv (manages the Python venv nyxstrike.sh syncs into) ─────────────
ENV UV_INSTALL_DIR=/usr/local/bin
RUN curl -LsSf https://astral.sh/uv/install.sh | sh

# ── Install all NyxStrike tool dependencies via nyxstrike.sh -t ──────────────
WORKDIR /opt/nyxstrike

# Copy the repo into the image
COPY . .

# Run tool install (apt/cargo tools only).
RUN apt-get update -qq && \
    chmod +x nyxstrike.sh && \
    bash nyxstrike.sh -t && \
    rm -rf /var/lib/apt/lists/*

# Add the Postgres backend driver so the image can run against the in-cluster
# Postgres (NYXSTRIKE_DB_BACKEND=postgres, DATABASE_URL=postgres://...). This is
# a no-op for the default SQLite backend. Reconciles the venv to base + tools +
# postgres from the pinned lock.
# NOTE: docker-entrypoint.sh resolves ROOT_DIR to the docker/ dir (where it
# lives) and execs `${ROOT_DIR}/nyxstrike-env/bin/python3` +
# `${ROOT_DIR}/nyxstrike_server.py`. So the venv AND the server must live under
# docker/ for the entrypoint to find them. (Previously the venv was built at
# /opt/nyxstrike/nyxstrike-env -> "No such file or directory" on every image.)
RUN UV_PROJECT_ENVIRONMENT=/opt/nyxstrike/docker/nyxstrike-env \
    uv sync --frozen --extra tools --extra postgres

# Copy the runtime entrypoint target into docker/ so ROOT_DIR-relative lookup works.
RUN cp -f /opt/nyxstrike/nyxstrike_server.py /opt/nyxstrike/docker/nyxstrike_server.py \
    && cp -f /opt/nyxstrike/nyxstrike.sh /opt/nyxstrike/docker/nyxstrike.sh

# ── Runtime config ─────────────────────────────────────────────────────────────
# Bind to 0.0.0.0 inside the container so the mapped port is reachable
ENV NYXSTRIKE_HOST=0.0.0.0
ENV NYXSTRIKE_PORT=8888

EXPOSE 8888

# ── Entrypoint ─────────────────────────────────────────────────────────────────
RUN chmod +x docker/docker-entrypoint.sh

ENTRYPOINT ["/opt/nyxstrike/docker/docker-entrypoint.sh"]
