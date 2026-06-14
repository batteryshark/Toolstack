"""Short-lived broker Store connections for the admin app.

The broker holds one long-lived Store connection; the admin app instead opens a
fresh connection per request and closes it promptly. WAL mode (see
``broker/store.py``) lets these coexist with the broker's connection on the same
file. The db path comes from the current ``BrokerRunConfig``, so the admin app and
the broker it supervises always read and write the same database.
"""

from __future__ import annotations

from contextlib import contextmanager

from broker.store import Store

from .broker_config import BrokerRunConfig


@contextmanager
def open_store(config: BrokerRunConfig):
    store = Store(config.db_path)
    try:
        yield store
    finally:
        store.close()
