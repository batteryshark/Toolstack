"""Serial HTTP transport bounds; no request worker threads or signal handlers."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
import http.client
import io
import time
import urllib.request


class LimitExceeded(RuntimeError):
    pass


class DeadlineReader(io.RawIOBase):
    def __init__(self, sock, deadline, inactivity, *, own=False, reader=None):
        self.sock, self.deadline, self.inactivity, self.own = sock, deadline, inactivity, own
        self.reader = reader

    def readable(self):
        return True

    def readinto(self, buffer):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("transport deadline exceeded")
        self.sock.settimeout(min(self.inactivity, remaining))
        return self.reader.readinto(buffer) if self.reader is not None else self.sock.recv_into(buffer)

    def close(self):
        if self.reader is not None:
            self.reader.close()
        elif self.own:
            self.sock.close()
        super().close()


@dataclass
class Budget:
    deadline: float
    remaining: int
    inactivity: float


_budget = ContextVar("toolstack_response_budget", default=None)


@contextmanager
def operation_bounds(duration, size):
    token = _budget.set(Budget(time.monotonic() + duration, size, min(duration, 5.0)))
    try:
        yield
        if time.monotonic() > _budget.get().deadline:
            raise TimeoutError("transport deadline exceeded")
    finally:
        _budget.reset(token)


class _Response(http.client.HTTPResponse):
    def __init__(self, sock, *args, **kwargs):
        budget = _budget.get()
        if budget is not None:
            # Preserve standard socket.makefile reference lifetime, including
            # TLS sockets (which cannot be duplicated).
            raw_sock = sock
            class SocketView:
                def makefile(self, mode):
                    return io.BufferedReader(DeadlineReader(raw_sock, budget.deadline,
                        budget.inactivity, reader=raw_sock.makefile("rb", buffering=0)))
            sock = SocketView()
        super().__init__(sock, *args, **kwargs)


class _Connection(http.client.HTTPConnection):
    response_class = _Response


class DeadlineHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        budget = _budget.get()
        if budget is not None:
            remaining = budget.deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("transport deadline exceeded")
            req.timeout = min(req.timeout, remaining, budget.inactivity)
        return self.do_open(_Connection, req)


class _SecureConnection(http.client.HTTPSConnection):
    response_class = _Response


class DeadlineHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        budget = _budget.get()
        if budget is not None:
            remaining = budget.deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("transport deadline exceeded")
            req.timeout = min(req.timeout, remaining, budget.inactivity)
        return self.do_open(_SecureConnection, req, context=self._context)


def chunks(response):
    """Incremental bytes including chunked bodies, capped across one execution."""
    budget = _budget.get()
    if budget is None:
        raise RuntimeError("missing execution budget")
    while True:
        if time.monotonic() >= budget.deadline:
            raise TimeoutError("transport deadline exceeded")
        chunk = response.read1(min(4096, budget.remaining + 1))
        if not chunk:
            return
        budget.remaining -= len(chunk)
        if budget.remaining < 0:
            raise LimitExceeded("tool response size exceeded")
        yield chunk


def read_response(response):
    return b"".join(chunks(response))
