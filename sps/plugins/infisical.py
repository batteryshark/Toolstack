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

from ..config import InfisicalBlock
from .base import SPSSecretsPlugin


class InfisicalPlugin(SPSSecretsPlugin):
    def __init__(self, block: InfisicalBlock, *, timeout: float = 15.0) -> None:
        if not block.host or not block.client_id or not block.client_secret:
            raise ValueError("InfisicalPlugin requires host/client_id/client_secret")
        self.host = block.host.rstrip("/")
        self.vault = block.vault
        self.environment = block.environment
        self.organization_slug = block.organization_slug
        self.client_id = block.client_id
        self.client_secret = block.client_secret
        self.timeout = timeout
        self._token: tuple[str, float] | None = None
        self._project_id: str | None = None

    def connect(self):
        self._access_token()  # pre-warm so first get_secret doesn't pay login cost
        self._ensure_project_id()
        return self

    # ---- ABC ----------------------------------------------------------------
    def get_secret(self, field: str, item: str) -> str:
        path = "/" + (item or self.vault).strip("/") if (item or self.vault) else "/"
        params = {
            "projectId": self._ensure_project_id(),
            "environment": self.environment,
            "secretPath": path,
            "viewSecretValue": "true",
            "expandSecretReferences": "true",
            "includeImports": "true",
        }
        body = self._http("GET", "/api/v4/secrets", params=params)
        for secret in self._iter(body):
            if secret.get("secretKey") == field:
                value = secret.get("secretValue")
                if not isinstance(value, str):
                    raise ValueError(
                        f"Infisical {self.vault}{path}/{field} has no string value"
                    )
                return value
        raise KeyError(f"Infisical secret {self.vault}{path}/{field} not found")

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
        for p in body.get("projects") or []:
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

    @staticmethod
    def _iter(body):
        if not isinstance(body, dict):
            return
        for s in body.get("secrets") or []:
            if isinstance(s, dict):
                yield s
        for imp in body.get("imports") or []:
            if isinstance(imp, dict):
                for s in imp.get("secrets") or []:
                    if isinstance(s, dict):
                        yield s

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
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.loads(resp.read().decode("utf-8"))
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
                transient = RuntimeError(
                    f"Infisical {method} {path}: {exc.reason} (network)"
                )
            if attempt < 2:
                time.sleep(0.25 * (2 ** attempt))
        raise transient or RuntimeError(
            f"Infisical {method} {path}: exhausted retries"
        )
