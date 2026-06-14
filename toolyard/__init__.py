"""Toolyard — the execution boundary.

Reads `toolyard.toml`, resolves each tool's secrets, and starts the tool so the
broker can forward approved calls to it on `127.0.0.1:<port>`. The broker is never
on the secret path. See ../plan.md.
"""
