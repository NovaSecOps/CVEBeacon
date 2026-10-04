"""Verified HTTPS push; exact retransmission is safe under receiver idempotence."""

import time
from urllib.parse import urlsplit

from ..common import AutomationError, Secret
from ..http import HTTPS, TransportError, endpoint
from .protocol import encode_envelope, envelope_json, load_pair


def push(filename, url, secret: Secret, *, ca_file=None, timeout=15, attempts=3, max_age_seconds=86400, transport=None):
    target = endpoint(url)
    if target.path != "/v1/snapshots" or type(attempts) is not int or not 1 <= attempts <= 3:
        raise AutomationError("ingestion_endpoint_invalid")
    source, inventory, manifest = load_pair(filename, max_age_seconds)
    body = encode_envelope(source, inventory, manifest)
    token = secret.resolve()
    if len(token) < 32:
        raise AutomationError("ingestion_credential_too_short")
    http = transport or HTTPS(url, ca_file=ca_file, timeout=timeout, max_response=65536)
    for attempt in range(attempts):
        try:
            response = http.request("POST", url, headers={"Authorization": "Bearer " + token, "X-CVEBeacon-Source": source, "Content-Type": "application/json"}, body=body)
        except TransportError:
            if attempt + 1 == attempts:
                raise AutomationError("upload_outcome_unknown") from None
        else:
            if response.status == 200:
                result = envelope_json(response.body, 65536)
                from ..common import digest
                if not isinstance(result, dict) or set(result) != {"status", "accepted_at", "generation"} or result["status"] not in {"accepted", "idempotent"} or result["generation"] != digest(inventory + b"\x00" + manifest):
                    raise AutomationError("upload_response_invalid")
                return {"source_id": source, **result}
            if response.status == 429:
                # Let the scheduler respect the complete delay; never clamp or busy retry.
                raise AutomationError("upload_rate_limited")
            if response.status not in {502, 503, 504}:
                raise AutomationError("upload_rejected")
            if attempt + 1 == attempts:
                raise AutomationError("upload_retry_exhausted")
        time.sleep(0.25 * 2 ** attempt)
    raise AutomationError("upload_retry_exhausted")
