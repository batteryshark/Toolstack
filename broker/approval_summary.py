"""Allowlisted approval presentation, not a claim that arbitrary text is secret-free.

Pointers are RFC6901 paths relative to arguments. Justification is NEVER shown.
The complete canonical action is private state; only its digest reaches Nod.
"""
import hashlib
import json
import re
import secrets
from itertools import islice


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def bound_request(caller_id, tool, op, generation, arguments, reason, nonce=None):
    action = canonical({"caller_id": caller_id, "tool": tool, "op": op,
                        "operation_generation": generation, "arguments": arguments, "reason": reason,
                        # Private random binding context prevents the public digest
                        # becoming an offline guessing oracle for a short password.
                        "nonce": nonce if nonce is not None else secrets.token_hex(32)})
    return action, hashlib.sha256(action.encode()).hexdigest()


def validate_fields(fields):
    if (not isinstance(fields, list) or len(fields) > 32
            or any(not isinstance(p, str) or not p.startswith("/") or "*" in p or len(p) > 256
                   or re.search(r"~(?![01])", p) for p in fields)
            or len(set(fields)) != len(fields)):
        raise ValueError("approval_fields must be <=32 unique non-root RFC6901 pointers (<=256 characters); '*' is forbidden")
    return tuple(fields)


def sensitive(name):
    name = re.sub(r"[^a-z0-9]", "", name.lower())
    return any(part in name for part in ("password", "passwd", "passphrase", "secret", "token", "credential",
                                         "apikey", "authorization", "cookie", "privatekey", "session", "bearer")) or name in {"pwd", "auth", "accesskey", "key", "pin", "otp", "ssn", "reason", "justification"}


def _mask(value, depth=0):
    if depth >= 4 and isinstance(value, (dict, list)):
        return "[OMITTED: nesting limit]"
    if isinstance(value, dict):
        result = {}
        for key, child in islice(value.items(), 16):
            if len(key) > 64:
                result["[OMITTED: long field name]"] = "[MASKED]"
            else:
                result[key] = "[MASKED]" if sensitive(key) else _mask(child, depth + 1)
        if len(value) > 16:
            result["[OMITTED]"] = f"{len(value)-16} additional fields"
        return result
    if isinstance(value, list):
        result = [_mask(child, depth + 1) for child in value[:16]]
        if len(value) > 16:
            result.append(f"[OMITTED: {len(value)-16} additional items]")
        return result
    if isinstance(value, str) and len(value) > 256:
        return value[:256] + "[TRUNCATED: remaining text omitted]"
    return value


def summarize(arguments, fields):
    entries = []
    size_omitted = 0
    omissions = ["Fields outside configured pointers are omitted.", "Agent justification is omitted."]
    if not fields:
        omissions.insert(0, "ALL arguments omitted: no approval_fields configured.")
    for pointer in fields:
        parts = [p.replace("~1", "/").replace("~0", "~") for p in pointer[1:].split("/")]
        value = arguments
        try:
            for part in parts:
                if isinstance(value, list):
                    if not re.fullmatch(r"0|[1-9][0-9]*", part):
                        raise KeyError(part)
                    value = value[int(part)]
                else:
                    value = value[part]
            safe = "[MASKED]" if any(sensitive(part) for part in parts) else _mask(value)
        except (KeyError, IndexError, TypeError, ValueError):
            safe = "[OMITTED: configured field not present]"
        entry = {"field": pointer, "value": safe}
        # Bound each field independently so an inflated early value cannot hide
        # later, small fields. Reserve space for the envelope and omission counts.
        if len(canonical(entry)) > 1000 or len(canonical(entries + [entry])) > 3600:
            size_omitted += 1
            entry = {"field": pointer, "value": "[OMITTED: summary size limit]"}
        if len(canonical(entries + [entry])) <= 3600:
            entries.append(entry)
    if size_omitted:
        omissions.append(f"Configured fields: {len(fields)}; values shown: {len(fields)-size_omitted}; "
                         f"omitted for summary size: {size_omitted} (labels included where space permits).")
        if size_omitted == len(fields):
            omissions.append("ALL configured field values omitted: summary size limit; 0 shown.")
    return canonical({"selected_fields": entries, "omissions": omissions})
