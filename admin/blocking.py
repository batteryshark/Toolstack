"""Bounded off-loop work; no service or unbounded executor queue."""
import asyncio
import functools
import threading
from concurrent.futures import ThreadPoolExecutor

from fastapi import HTTPException


class BlockingWork:
    def __init__(self, limit=1):
        self._slots = threading.BoundedSemaphore(limit)
        self._executor = ThreadPoolExecutor(max_workers=limit, thread_name_prefix="admin-work")

    async def run(self, fn, *args, **kwargs):
        if not self._slots.acquire(blocking=False):
            raise HTTPException(status_code=503, detail="Admin work capacity busy; retry later")
        try:
            future = self._executor.submit(functools.partial(fn, *args, **kwargs))
        except BaseException:
            self._slots.release()
            raise
        # Release only when actual work finishes, even if the caller disconnects.
        future.add_done_callback(lambda _: self._slots.release())
        return await asyncio.shield(asyncio.wrap_future(future))


work = BlockingWork()
