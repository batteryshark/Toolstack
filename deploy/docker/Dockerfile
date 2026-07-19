# Toolstack one-box: broker + admin + toolyard in a single image, for a laptop.
#
# The admin (uvicorn) is the entrypoint; it supervises the broker as a subprocess and
# runs tools with the PROCESS runner, so the whole stack shares ONE container loopback.
# That deliberately avoids docker-out-of-docker: tool containers would publish to the
# host loopback, which the in-container broker can't reach at 127.0.0.1. Tools run as
# processes inside the box instead; less isolation, but correct and simple for a laptop.
#
# All state (admin config, broker SQLite, the encrypted vault, toolyard state) honors
# XDG_CONFIG_HOME / XDG_STATE_HOME, so pointing both at /data persists everything on one
# mounted volume. See deploy/docker/README.md.

FROM python:3.12-slim

WORKDIR /app

# git: the admin shells out to it to import a tool from a GitHub repo (add-from-repo). Kept in a
# standalone layer (before the code COPY) so it stays cached across code changes.
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

# stdlib stack (editable) + the vault extra (cryptography) + the admin's runtime deps.
# cryptography/fastapi/uvicorn ship manylinux/pure-python wheels, so no build toolchain.
COPY pyproject.toml ./
COPY broker/ broker/
COPY toolyard/ toolyard/
COPY client/ client/
COPY admin/ admin/
COPY tools/ tools/
RUN pip install --no-cache-dir -e '.[vault]' \
    && pip install --no-cache-dir -r admin/requirements.txt

ENV XDG_CONFIG_HOME=/data/config \
    XDG_STATE_HOME=/data/state \
    TOOLSTACK_RUNNER=process \
    TOOLSTACK_TOOLS_ROOT=/app/tools \
    # Bind 0.0.0.0 INSIDE the container so Docker can publish the ports. The boundary
    # then lives in the publish mapping: publish to 127.0.0.1:<port> on the HOST only
    # (docker-compose.yml does this). Never run this image with a 0.0.0.0 publish.
    # The *_ALLOW_NONLOOPBACK opt-ins are required because admin/broker fail closed on a
    # non-loopback bind; here it's safe precisely because of the loopback publish mapping.
    TOOLSTACK_ADMIN_HOST=0.0.0.0 \
    TOOLSTACK_BROKER_HOST=0.0.0.0 \
    TOOLSTACK_ADMIN_ALLOW_NONLOOPBACK=1 \
    TOOLSTACK_BROKER_ALLOW_NONLOOPBACK=1
# Phase 5: secrets are resolved through SPS (Infisical / Hashicorp Vault / localfile);
# the operator configures sps.env at deploy time, the tool pulls at boot.

# 8780 = admin UI; 8765 = broker (point your agent here). Published to host loopback only.
EXPOSE 8765 8780

# The admin process is the only foreground process; it supervises the broker + tools
# as subprocesses (mirroring the toolyard's ProcessRunner).
CMD ["/usr/local/bin/admin", "serve", "--host", "0.0.0.0", "--port", "8780"]
