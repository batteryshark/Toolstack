FROM python:3.12-slim
WORKDIR /app
# Build from repository root: docker build -f tools/echo_mcp/Dockerfile .
COPY tools/echo_mcp/app.py tools/echo_mcp/toolyard.toml ./
COPY sps /app/sps
# API channel credential is independent of SPS. Docker+SPS remains unsupported.
CMD ["python3", "app.py"]
