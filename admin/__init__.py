"""Toolstack admin web app: the operator's control panel for the whole stack.

A small FastAPI app for local/homelab use that **runs the broker** (starts/stops
the broker process), **manages clients** (callers, tokens, policies), and shows
**requests and audit**. It is the one Toolstack component allowed runtime
dependencies (FastAPI + uvicorn); the broker, toolyard, and client stay
zero-dependency stdlib.

It reaches broker state two ways, because the broker has no admin API:
  * **data**: opens ``broker.store.Store`` directly on the same SQLite file and
    mutates through ``broker.operations`` (the same code path as ``brokerctl``,
    so one shared audit trail);
  * **lifecycle**: supervises the broker process via ``os.posix_spawn`` /
    ``killpg``, mirroring ``toolyard.runner``.

Binds 127.0.0.1 only. See README.md and ../plan.md.
"""
