"""Finite SPS socket budgets. DNS remains a synchronous OS operation.

Late resolver/connect results are closed before credentials are transmitted.
No retries here: a failed mutation response has an unknown outcome.
"""
import contextvars
import functools
import http.client
import io
import math
import socket
import ssl
import time
import urllib.request
import urllib.error

MAX_RESPONSE = 8 * 1024 * 1024
_active = contextvars.ContextVar("sps_budget", default=None)


def valid_timeout(value):
    if isinstance(value, bool) or not math.isfinite(value) or not 0 < value <= 300:
        raise ValueError("timeout must be finite and in (0, 300]")
    return value


class Budget:
    def __init__(self, timeout, cap=MAX_RESPONSE):
        self.end = time.monotonic() + valid_timeout(timeout)
        self.left = cap

    def remaining(self):
        remaining = self.end - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("SPS operation deadline exceeded")
        return remaining

    def idle(self):
        return min(5.0, self.remaining())

    def count(self, size):
        self.left -= size
        if self.left < 0:
            raise ValueError("SPS response exceeds limit")


def operation(fn):
    @functools.wraps(fn)
    def call(self, *args, **kwargs):
        token = None if _active.get() is not None else _active.set(Budget(self.timeout))
        try:
            return fn(self, *args, **kwargs)
        except KeyError:
            raise KeyError("SPS provider value unavailable") from None
        except ValueError:
            raise ValueError("SPS provider invalid response") from None
        except urllib.error.HTTPError as exc:
            exc.close()
            raise RuntimeError("SPS provider operation failed") from None
        except Exception:
            raise RuntimeError("SPS provider operation failed; mutation outcome may be unknown") from None
        finally:
            if token is not None:
                _active.reset(token)
    return call


def connect_socket(host, port, budget):
    budget.remaining()
    addresses = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    budget.remaining()  # OS resolver is not hard-preemptible.
    for family, kind, proto, _, address in addresses:
        raw = socket.socket(family, kind, proto)
        try:
            raw.settimeout(budget.idle())
            raw.connect(address)
            budget.remaining()
            return raw
        except OSError:
            raw.close()
            budget.remaining()
    raise OSError("SPS connection failed")


class _Reader(io.RawIOBase):
    def __init__(self, sock, budget):
        self.sock, self.budget = sock, budget
        # Own an ordinary SocketIO reference, not merely a Python socket
        # reference: urllib closes the connection socket after response headers.
        # socket.makefile keeps the descriptor alive until this reader closes,
        # for both TCP and SSLSocket (which does not support dup()).
        self._raw = sock.makefile("rb", buffering=0)

    def readable(self):
        return True

    def readinto(self, target):
        self.sock.settimeout(self.budget.idle())
        size = self._raw.readinto(target)
        self.budget.remaining()
        return size

    def close(self):
        try:
            if hasattr(self, "_raw"):
                self._raw.close()
        finally:
            super().close()


class _Socket:
    def __init__(self, sock, budget):
        self.sock, self.budget = sock, budget

    def __getattr__(self, name):
        return getattr(self.sock, name)

    def makefile(self, *args, **kwargs):
        reader = _Reader(self.sock, self.budget)
        try:
            return io.BufferedReader(reader)
        except BaseException:
            reader.close()
            raise

    def sendall(self, data):
        view = memoryview(data)
        while view:
            self.sock.settimeout(self.budget.idle())
            size = self.sock.send(view[:65536])
            self.budget.remaining()
            if not size:
                raise OSError("SPS connection closed")
            view = view[size:]


class _HTTP(http.client.HTTPConnection):
    def connect(self):
        budget = _active.get()
        raw = connect_socket(self.host, self.port, budget)
        try:
            budget.remaining()  # DNS/connect cannot be preempted; refuse late result.
            if isinstance(self, _HTTPS):
                raw.settimeout(budget.idle())
                raw = self._context.wrap_socket(raw, server_hostname=self.host,
                                                do_handshake_on_connect=False)
                raw.settimeout(budget.idle())
                raw.do_handshake()
                budget.remaining()
            self.sock = _Socket(raw, budget)
        except BaseException:
            raw.close()
            raise


class _HTTPS(_HTTP, http.client.HTTPSConnection):
    pass


class _HTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_HTTP, req)


class _HTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_HTTPS, req, context=ssl.create_default_context())


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def urlopen(req, timeout=None):
    # Ignore ambient proxies: credentials go only to the configured origin.
    return urllib.request.build_opener(urllib.request.ProxyHandler({}),
        _HTTPHandler(), _HTTPSHandler(), _NoRedirect()).open(req, timeout=timeout)


def read_response(resp):
    budget = _active.get()
    chunks = []
    while True:
        budget.remaining()
        chunk = resp.read( min(65536, budget.left + 1))
        budget.remaining()
        budget.count(len(chunk))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
