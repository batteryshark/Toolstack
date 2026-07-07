"""Gateway: routing, auth, body validation, and outcome -> HTTP mapping."""

import json
import unittest

from broker import approval
from broker.gateway import handle
from broker.identity import hash_token
from broker.ratelimit import RateLimiter

from .support import BrokerTestCase, FakeSurface, seed_caller

CATALOG = {"echo": {"say": "low", "secret": "high", "shout": "low"}}


_DEFAULT_BODY = object()  # distinguishes "no body passed" from an explicit None


def _bearer(token):
    return {"Authorization": f"Bearer {token}"}


class Health(BrokerTestCase):
    def test_open_without_auth(self):
        r = handle("GET", "/v1/health", {}, {}, self.make_ctx())
        self.assertEqual(r.status, 200)
        self.assertEqual(r.body, {"status": "ok"})

    def test_health_is_not_audited(self):
        # Liveness probes must stay out of the audit trail (they are polled often).
        ctx = self.make_ctx()
        handle("GET", "/v1/health", {}, {}, ctx)
        self.assertEqual(ctx.audit.events(), [])


class Auth(BrokerTestCase):
    def test_unauthenticated_action_401(self):
        r = handle("POST", "/v1/actions/echo.say", {}, {"arguments": {}}, self.make_ctx())
        self.assertEqual(r.status, 401)

    def test_bad_token_401(self):
        r = handle("POST", "/v1/actions/echo.say", _bearer("nope"), {"arguments": {}}, self.make_ctx())
        self.assertEqual(r.status, 401)

    def test_revoked_token_401(self):
        ctx = self.make_ctx(catalog=CATALOG)
        token = seed_caller(ctx.store, "hermes", allow=["echo.say"])
        ctx.store.revoke_token(hash_token(token))
        r = handle("POST", "/v1/actions/echo.say", _bearer(token), {"arguments": {}}, ctx)
        self.assertEqual(r.status, 401)

    def test_authenticated_unknown_route_404(self):
        ctx = self.make_ctx(catalog=CATALOG)
        token = seed_caller(ctx.store, "hermes", allow=["echo.say"])
        r = handle("GET", "/v1/requests", _bearer(token), {}, ctx)
        self.assertEqual(r.status, 404)


class Actions(BrokerTestCase):
    def setUp(self):
        self.ctx = self.make_ctx(catalog=CATALOG)
        self.token = seed_caller(
            self.ctx.store, "hermes", allow=["echo.say"], review=["echo.shout"]
        )

    def _post(self, spec, body=_DEFAULT_BODY, token=None):
        headers = _bearer(self.token if token is None else token)
        actual = {"arguments": {}} if body is _DEFAULT_BODY else body
        return handle("POST", f"/v1/actions/{spec}", headers, actual, self.ctx)

    def test_allow_returns_200_with_result(self):
        r = self._post("echo.say", {"arguments": {"m": "hi"}})
        self.assertEqual(r.status, 200)
        self.assertEqual(r.body["status"], "ok")
        self.assertEqual(r.body["result"], {"echoed": {"m": "hi"}})
        self.assertIn("request_id", r.body)

    def test_denied_returns_403(self):
        r = self._post("echo.secret")  # registered, but not granted
        self.assertEqual(r.status, 403)

    def test_review_returns_202(self):
        r = self._post("echo.shout")
        self.assertEqual(r.status, 202)
        self.assertEqual(r.body["status"], "pending_approval")

    def test_unknown_tool_returns_404(self):
        r = self._post("echo.ghost")  # not in the registry
        self.assertEqual(r.status, 404)

    def test_malformed_action_path_returns_400(self):
        for spec in ["echo", "echo.", ".say", "echo.say.extra"]:
            with self.subTest(spec=spec):
                self.assertEqual(self._post(spec).status, 400)

    def test_malformed_body_returns_400(self):
        self.assertEqual(self._post("echo.say", None).status, 400)          # bad JSON
        self.assertEqual(self._post("echo.say", []).status, 400)            # not an object
        self.assertEqual(self._post("echo.say", {"arguments": 7}).status, 400)  # args not object

    def test_token_value_never_logged(self):
        self._post("echo.say")
        blob = json.dumps(self.ctx.audit.events())
        self.assertNotIn(self.token, blob)


class RestEnvelopeValidation(BrokerTestCase):
    def setUp(self):
        self.meta = {
            "verb": "POST",
            "path_template": "/login",
            "base_url_host": "api.example.test",
            "body_kind": "text",
        }
        self.ctx = self.make_ctx(catalog={"jira": {"login": "write"}}, tool_type="rest",
                                 rest_meta=self.meta)
        self.token = seed_caller(self.ctx.store, "hermes", allow=["jira.login"])

    def _post(self, arguments):
        return handle("POST", "/v1/actions/jira.login", _bearer(self.token),
                      {"arguments": arguments}, self.ctx)

    def test_text_body_required_and_must_be_string(self):
        self.assertEqual(self._post({}).status, 400)
        r = self._post({"body": {"not": "string"}})
        self.assertEqual(r.status, 400)
        self.assertEqual(r.body["error"], "invalid_envelope")

    def test_variables_and_headers_must_be_string_maps(self):
        for arguments in (
            {"variables": [], "body": "{}"},
            {"variables": {"id": 7}, "body": "{}"},
            {"headers": {"X": 1}, "body": "{}"},
        ):
            with self.subTest(arguments=arguments):
                self.assertEqual(self._post(arguments).status, 400)

    def test_valid_text_envelope_submits(self):
        r = self._post({"variables": {"id": "u42"}, "headers": {"X": "y"}, "body": "{}"})
        self.assertEqual(r.status, 200)
        self.assertEqual(r.body["status"], "ok")

    def test_none_body_rejects_present_body(self):
        ctx = self.make_ctx(catalog={"jira": {"get_user": "read"}}, tool_type="rest",
                            rest_meta={**self.meta, "body_kind": "none"})
        token = seed_caller(ctx.store, "hermes", allow=["jira.get_user"])
        r = handle("POST", "/v1/actions/jira.get_user", _bearer(token),
                   {"arguments": {"body": ""}}, ctx)
        self.assertEqual(r.status, 400)

    def test_binary_body_must_be_base64(self):
        ctx = self.make_ctx(catalog={"jira": {"upload": "write"}}, tool_type="rest",
                            rest_meta={**self.meta, "body_kind": "binary"})
        token = seed_caller(ctx.store, "hermes", allow=["jira.upload"])
        r = handle("POST", "/v1/actions/jira.upload", _bearer(token),
                   {"arguments": {"body": "not base64"}}, ctx)
        self.assertEqual(r.status, 400)


class RequestStatus(BrokerTestCase):
    def _bearer(self, token):
        return {"Authorization": f"Bearer {token}"}

    def test_poll_pending_then_approved_runs_it(self):
        surface = FakeSurface(approval.PENDING)
        ctx = self.make_ctx(catalog={"echo": {"shout": "high"}}, surface=surface)
        token = seed_caller(ctx.store, "hermes", review=["echo.shout"])

        submit = handle("POST", "/v1/actions/echo.shout", self._bearer(token),
                        {"arguments": {"m": "hi"}}, ctx)
        self.assertEqual(submit.status, 202)
        rid = submit.body["request_id"]

        poll = handle("GET", f"/v1/requests/{rid}", self._bearer(token), {}, ctx)
        self.assertEqual(poll.status, 200)
        self.assertEqual(poll.body["status"], "pending_approval")

        surface.set(approval.APPROVED, approver="owner")
        poll2 = handle("GET", f"/v1/requests/{rid}", self._bearer(token), {}, ctx)
        self.assertEqual(poll2.body["status"], "ok")
        self.assertEqual(poll2.body["result"], {"echoed": {"m": "hi"}})

    def test_cannot_read_another_callers_request(self):
        ctx = self.make_ctx(catalog={"echo": {"say": "low"}})
        owner = seed_caller(ctx.store, "hermes", allow=["echo.say"])
        sub = handle("POST", "/v1/actions/echo.say", self._bearer(owner), {"arguments": {}}, ctx)
        rid = sub.body["request_id"]
        other = seed_caller(ctx.store, "mallory", allow=["echo.say"])
        r = handle("GET", f"/v1/requests/{rid}", self._bearer(other), {}, ctx)
        self.assertEqual(r.status, 404)

    def test_unknown_request_404(self):
        ctx = self.make_ctx()
        token = seed_caller(ctx.store, "hermes")
        r = handle("GET", "/v1/requests/999", self._bearer(token), {}, ctx)
        self.assertEqual(r.status, 404)


class Hardening(BrokerTestCase):
    def _bearer(self, token):
        return {"Authorization": f"Bearer {token}"}

    def test_rate_limit_returns_429(self):
        ctx = self.make_ctx(catalog={"echo": {"say": "low"}})
        ctx.rate_limiter = RateLimiter(1)
        token = seed_caller(ctx.store, "hermes", allow=["echo.say"])
        h = self._bearer(token)
        self.assertEqual(handle("POST", "/v1/actions/echo.say", h, {"arguments": {}}, ctx).status, 200)
        self.assertEqual(handle("POST", "/v1/actions/echo.say", h, {"arguments": {}}, ctx).status, 429)

    def test_reason_is_redacted_in_audit(self):
        ctx = self.make_ctx(catalog={"echo": {"say": "low"}})
        token = seed_caller(ctx.store, "hermes", allow=["echo.say"])
        reason = "rotate token " + "Z" * 40
        handle("POST", "/v1/actions/echo.say", self._bearer(token),
               {"arguments": {}, "reason": reason}, ctx)
        blob = json.dumps(ctx.audit.events())
        self.assertNotIn("Z" * 40, blob)
        self.assertIn("[redacted]", blob)


class Discovery(BrokerTestCase):
    def _bearer(self, token):
        return {"Authorization": f"Bearer {token}"}

    def test_tools_lists_only_allowed_with_effects(self):
        ctx = self.make_ctx(catalog={"echo": {"say": "low", "skip": "high", "secret": "high"}})
        token = seed_caller(ctx.store, "hermes", allow=["echo.say"], review=["echo.skip"])
        r = handle("GET", "/v1/tools", self._bearer(token), {}, ctx)
        self.assertEqual(r.status, 200)
        self.assertEqual(r.body["caller"], "hermes")
        ops = {f"{t['tool']}.{t['op']}": t["effect"] for t in r.body["tools"]}
        self.assertEqual(ops, {"echo.say": "allow", "echo.skip": "review"})  # echo.secret omitted

    def test_describe_allowed_op(self):
        ctx = self.make_ctx(catalog={"echo": {"say": "low"}})
        token = seed_caller(ctx.store, "hermes", allow=["echo.say"])
        r = handle("GET", "/v1/tools/echo.say", self._bearer(token), {}, ctx)
        self.assertEqual(r.status, 200)
        self.assertEqual(r.body["op"], "say")
        self.assertEqual(r.body["effect"], "allow")

    def test_describe_denied_op_is_404(self):
        ctx = self.make_ctx(catalog={"echo": {"secret": "high"}})
        token = seed_caller(ctx.store, "hermes", allow=["echo.say"])  # not granted echo.secret
        r = handle("GET", "/v1/tools/echo.secret", self._bearer(token), {}, ctx)
        self.assertEqual(r.status, 404)


class CorrelationId(BrokerTestCase):
    def test_supplied_is_propagated(self):
        r = handle("GET", "/v1/health", {"X-Correlation-Id": "abc123"}, {}, self.make_ctx())
        self.assertEqual(r.correlation_id, "abc123")

    def test_minted_when_absent(self):
        r = handle("GET", "/v1/health", {}, {}, self.make_ctx())
        self.assertTrue(r.correlation_id)


if __name__ == "__main__":
    unittest.main()
