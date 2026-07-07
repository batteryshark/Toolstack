"""Secret-update rules for rest forwarder responses."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import socket
import urllib.parse
import xml.etree.ElementTree as ET

from .config import Operation, SecretUpdateRule

log = logging.getLogger(__name__)

_MAX_SECRET_VALUE = 8 * 1024
_WRITE_TIMEOUT = 5.0


class RuleError(RuntimeError):
    """A secret-update rule failed."""

    def __init__(self, code: str, detail: str = "", **fields) -> None:
        super().__init__(detail or code)
        self.code = code
        self.detail = detail or code
        self.fields = fields

    def envelope(self) -> dict:
        obj = {"error": self.code}
        if self.detail:
            obj["detail"] = self.detail
        obj.update(self.fields)
        return obj


def apply_secret_update_rules(op: Operation, response: dict) -> None:
    """Apply matching secret-update rules for a successful response envelope.

    Extraction is all-or-nothing: every matching rule must extract a bounded
    string before any write occurs. Writes then go through the existing
    per-tool write-proxy.
    """
    rules = [rule for rule in op.secret_update_rules if match_status(rule.match_status, int(response["status"]))]
    if not rules:
        return
    extracted: list[tuple[str, str, SecretUpdateRule]] = []
    try:
        for rule in rules:
            value = extract_value(rule, response.get("body", ""))
            if len(value.encode("utf-8")) > _MAX_SECRET_VALUE:
                raise RuleError("rule_extraction_failed", "extracted secret value exceeds 8KB",
                                secret=rule.secret_name)
            extracted.append((rule.secret_name, value, rule))
    except RuleError:
        raise
    except Exception as exc:
        raise RuleError("rule_extraction_failed", type(exc).__name__) from exc

    written: list[tuple[str, str]] = []
    for name, value, rule in extracted:
        try:
            status, body = write_secret_via_proxy(name, value)
        except OSError as exc:
            _log_partial(written)
            raise RuleError("secret_update_failed", type(exc).__name__, secret=name) from exc
        if status != 200:
            _log_partial(written)
            reason = body.get("error") if isinstance(body, dict) else None
            raise RuleError("secret_update_failed", reason or f"write-proxy status {status}", secret=name)
        fingerprint = hashlib.sha256(value.encode("utf-8")).hexdigest()
        written.append((name, fingerprint))
        log.info("updated secret via write-proxy: %s sha256=%s rule=%s",
                 name, fingerprint, rule.response_type)


def match_status(spec: str, status: int) -> bool:
    for part in spec.split("|"):
        part = part.strip().lower()
        if not part:
            continue
        if len(part) == 3 and part[0].isdigit() and part[1:] == "xx":
            if status // 100 == int(part[0]):
                return True
        elif part.isdigit() and status == int(part):
            return True
    return False


def extract_value(rule: SecretUpdateRule, body: str) -> str:
    if rule.response_type == "json":
        return _extract_json(body, rule.extract_path)
    if rule.response_type == "form":
        values = urllib.parse.parse_qs(body, keep_blank_values=True)
        found = values.get(rule.extract_path)
        if not found:
            raise RuleError("rule_extraction_failed", "form field not found", secret=rule.secret_name)
        return found[0]
    if rule.response_type == "plaintext":
        match = re.search(rule.extract_path, body)
        if not match or match.lastindex is None:
            raise RuleError("rule_extraction_failed", "regex group not found", secret=rule.secret_name)
        return match.group(1)
    if rule.response_type == "xml":
        return _extract_xml(body, rule.extract_path, rule.secret_name)
    raise RuleError("rule_extraction_failed", "unsupported response type", secret=rule.secret_name)


def _extract_json(body: str, path: str) -> str:
    try:
        cur = json.loads(body)
    except json.JSONDecodeError as exc:
        raise RuleError("rule_extraction_failed", "invalid json") from exc
    for part in path.split("."):
        if isinstance(cur, list) and part.isdigit():
            idx = int(part)
            try:
                cur = cur[idx]
            except IndexError as exc:
                raise RuleError("rule_extraction_failed", "json index not found") from exc
        elif isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            raise RuleError("rule_extraction_failed", "json path not found")
    if not isinstance(cur, str):
        raise RuleError("rule_extraction_failed", "json path did not yield a string")
    return cur


def _extract_xml(body: str, path: str, secret_name: str) -> str:
    attr = None
    elem_path = path
    if "/@" in path:
        elem_path, attr = path.rsplit("/@", 1)
        if not attr:
            raise RuleError("rule_extraction_failed", "xml attribute is empty", secret=secret_name)
    try:
        root = ET.fromstring(body)
    except ET.ParseError as exc:
        raise RuleError("rule_extraction_failed", "invalid xml", secret=secret_name) from exc
    try:
        found = root.findall(elem_path)
    except SyntaxError as exc:
        raise RuleError("rule_extraction_failed", "invalid xml path", secret=secret_name) from exc
    if not found:
        raise RuleError("rule_extraction_failed", "xml path not found", secret=secret_name)
    if attr:
        value = found[0].get(attr)
        if value is None:
            raise RuleError("rule_extraction_failed", "xml attribute not found", secret=secret_name)
        return value
    if found[0].text is None:
        raise RuleError("rule_extraction_failed", "xml element has no text", secret=secret_name)
    return found[0].text


def write_secret_via_proxy(name: str, value: str, timeout: float = _WRITE_TIMEOUT) -> tuple[int, dict]:
    sock_path = os.environ.get("TOOLYARD_SECRETS_SOCKET")
    if not sock_path:
        raise RuntimeError("no write-proxy socket")
    payload = json.dumps({"value": value, "reason": "rest secret_update_rule"}).encode("utf-8")
    safe_name = urllib.parse.quote(name, safe="")
    request = (
        f"POST /v1/secrets/{safe_name} HTTP/1.1\r\n"
        "Host: toolyard\r\n"
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(payload)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii") + payload
    conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    conn.settimeout(timeout)
    try:
        conn.connect(sock_path)
        conn.sendall(request)
        chunks = []
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        conn.close()
    head, _, body = b"".join(chunks).partition(b"\r\n\r\n")
    fields = head.split(b" ", 2)
    status = int(fields[1]) if len(fields) > 1 and fields[1].isdigit() else 0
    try:
        parsed = json.loads(body or b"{}")
    except json.JSONDecodeError:
        parsed = {}
    return status, parsed if isinstance(parsed, dict) else {}


def _log_partial(written: list[tuple[str, str]]) -> None:
    if written:
        log.warning("secret update failed after partial writes: %s", written)
