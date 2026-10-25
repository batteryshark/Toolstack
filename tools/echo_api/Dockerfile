FROM python:3.12-slim
WORKDIR /app
# Build from repository root: docker build -f tools/echo_api/Dockerfile .
COPY tools/echo_api/app.py tools/echo_api/toolyard.toml ./
COPY sps /app/sps
# API channel credential is independent of SPS. Docker+SPS remains unsupported.
CMD ["python3", "app.py"]
