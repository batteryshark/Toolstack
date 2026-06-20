FROM python:3.12-slim
WORKDIR /app
COPY app.py .
# Secrets arrive at /run/secrets (tmpfs or mount); the port comes via TOOLSTACK_PORT.
# The tool holds no broker or secret-backend credential. Stdlib-only REST key-value store.
CMD ["python3", "app.py"]
