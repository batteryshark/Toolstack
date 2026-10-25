"""Infisical plugin for SPS.

Lifted from toolyard/secrets.InfisicalBackend with the same HTTP shapes and
retry discipline. The class now extends SPSSecretsPlugin instead of being
passed around as a duck-typed resolve/update pair.

Retry / HTTP-error mapping preserved from the source so SRE expectations
match the deprecated backend.
"""
from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request

from ..config import InfisicalBlock, validate_provider_url
from .base import SPSSecretsPlugin
from .. import transport


class InfisicalPlugin(SPSSecretsPlugin):
    def __init__(self, block: InfisicalBlock, *, timeout: float = 15.0) -> None:
        if not block.host or not block.client_id or not block.client_secret:
            raise ValueError("InfisicalPlugin requires host/client_id/client_secret")
        self.host = validate_provider_url(block.host)
        self.vault = block.vault
        self.environment = block.environment
        self.organization_slug = block.organization_slug
        self.client_id = block.client_id
        self.client_secret = block.client_secret
        self.timeout = transport.valid_timeout(timeout)
        self._token: tuple[str, float] | None = None
        self._project_id: str | None = None

    @transport.operation
    def connect(self):
        self._access_token()  # pre-warm so first get_secret doesn't pay login cost
        self._ensure_project_id()
        return self

    # ---- ABC ----------------------------------------------------------------
    @transport.operation
    def get_secret(self, field: str, item: str) -> str:
        path = "/" + (item or self.vault).strip("/") if (item or self.vault) else "/"
        params = {
            "projectId": self._ensure_project_id(),
            "environment": self.environment,
            "secretPath": path,
            "viewSecretValue": "true",
            "expandSecretReferences": "true",
            "includeImports": "true",
            "type": "shared",
        }
        # Official v4 getSecretByNameV4 contract (see handoff evidence).
        # References/import lookup stay server-side; never list the folder.
        body = self._http("GET", f"/api/v4/secrets/{urllib.parse.quote(field, safe='')}", params=params)
        secret = body.get("secret") if isinstance(body, dict) else None
        if not isinstance(secret, dict) or secret.get("secretKey") != field:
            raise KeyError("Infisical narrow response did not match requested secret")
        value = secret.get("secretValue")
        if not isinstance(value, str) or secret.get("secretValueHidden") is True:
            raise ValueError("Infisical narrow response has no readable string value")
        return value

    @transport.operation
    def write_secret(self, field: str, item: str, value: str) -> None:
        path = "/" + (item or self.vault).strip("/") if (item or self.vault) else "/"
        body = {
            "projectId": self._ensure_project_id(),
            "environment": self.environment,
            "secretValue": value,
            "secretPath": path,
            "type": "shared",
        }
        self._http(
            "PATCH",
            f"/api/v4/secrets/{urllib.parse.quote(field, safe='')}",
            json_body=body,
        )

    # ---- private -----------------------------------------------------------
    def _access_token(self) -> str:
        now = time.time()
        cached = self._token
        if cached and now < cached[1] - 30:
            return cached[0]
        body = {"clientId": self.client_id, "clientSecret": self.client_secret}
        if self.organization_slug:
            body["organizationSlug"] = self.organization_slug
        payload = self._http(
            "POST", "/api/v1/auth/universal-auth/login", json_body=body, authless=True
        )
        token = payload.get("accessToken")
        if not isinstance(token, str) or not token:
            raise ValueError("Infisical login did not return accessToken")
        ttl = payload.get("expiresIn")
        self._token = (token, now + float(ttl) if isinstance(ttl, (int, float)) else now + 600)
        return token

    def _ensure_project_id(self) -> str:
        if self._project_id:
            return self._project_id
        body = self._http("GET", "/api/v1/projects")
        projects = [p for p in body.get("projects") or [] if isinstance(p, dict)]
        exact = [p for p in projects if self.vault in (p.get("id"), p.get("_id"))]
        matches = exact or [p for p in projects if self.vault in (p.get("name"), p.get("slug"))]
        if len(matches) > 1:
            raise ValueError("ambiguous Infisical project selector")
        for p in matches:
            if not isinstance(p, dict):
                continue
            ids = {p.get(k) for k in ("id", "_id", "name", "slug")}
            if self.vault in ids:
                pid = p.get("id") or p.get("_id")
                if not isinstance(pid, str) or not pid:
                    raise ValueError(f"Infisical project {self.vault!r} has no id")
                self._project_id = pid
                return pid
        raise KeyError(f"Infisical project {self.vault!r} not found")

    def _http(self, method, path, *, params=None, json_body=None, authless=False):
        url = self.host + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        headers = {"Accept": "application/json"}
        data = None
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if not authless:
            headers["Authorization"] = "Bearer " + self._access_token()
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        transient: RuntimeError | None = None
        for attempt in range(3):
            try:
                with transport.urlopen(req, timeout=transport._active.get().idle()) as resp:
                    return json.loads(transport.read_response(resp).decode("utf-8"))
            except urllib.error.HTTPError as exc:
                code = exc.code
                exc.close()
                if code in (401, 403):
                    raise RuntimeError(
                        f"Infisical {method} {path}: HTTP {code} (auth)"
                    ) from exc
                if code != 429 and code < 500:
                    raise RuntimeError(
                        f"Infisical {method} {path}: HTTP {code}"
                    ) from exc
                transient = RuntimeError(
                    f"Infisical {method} {path}: HTTP {code} (transient)"
                )
            except urllib.error.URLError as exc:
                transient = RuntimeError("SPS provider network failure")
            if method != "GET":
                raise RuntimeError("SPS provider mutation outcome unknown") from None
            if attempt < 2:
                budget = transport._active.get()
                delay = 0.25 * (2 ** attempt)
                if delay >= budget.remaining():
                    raise TimeoutError("SPS operation deadline exceeded")
                time.sleep(delay)
                budget.remaining()
        raise transient or RuntimeError(
            f"Infisical {method} {path}: exhausted retries"
        )
