"""Bounded HTTP transport shared by all remote-source adapters."""

from __future__ import annotations

import email.utils
import logging
import math
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx

from .config import HttpConfig
from .errors import SourceError

RETRYABLE_STATUS = {429, 500, 502, 503, 504}
THROTTLE_STATUS = {403, 429}


@dataclass(slots=True)
class Throttle:
    """Bounded backoff shared by requests to one upstream host per run.

    The first successful response marks the host as reachable. Later HTTP 403
    or 429 responses then count as throttling instead of a permanent rejection.
    Waits are bounded per retry and in total, and the caller's ``sleep`` keeps
    the wait interruptible.
    """

    sleep: Callable[[float], None] = time.sleep
    delays: tuple[float, ...] = (60.0, 120.0, 240.0)
    maximum_delay: float = 240.0
    budget_seconds: float = 600.0
    maximum_retries: int = 20
    succeeded: bool = False
    count: int = 0
    waited: float = 0.0

    def wait(self, retry_after: float | None = None) -> bool:
        """Wait when the budget allows another retry, and report whether to retry."""
        if self.count >= self.maximum_retries:
            return False
        remaining = self.budget_seconds - self.waited
        if remaining <= 0:
            return False
        if retry_after is None:
            delay = self.delays[min(self.count, len(self.delays) - 1)]
            delay = min(max(delay, 0.0), self.maximum_delay, remaining)
        else:
            delay = min(max(retry_after, 0.0), self.maximum_delay)
            if delay > remaining:
                return False
        self.sleep(delay)
        self.count += 1
        self.waited += delay
        return True


@dataclass(frozen=True, slots=True)
class HttpResult:
    """One bounded HTTP response, with a body that is never logged."""

    status_code: int
    headers: Mapping[str, str]
    body: bytes


class HttpClient:
    def __init__(
        self,
        config: HttpConfig,
        *,
        client: httpx.Client | None = None,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        # httpx INFO records include full URLs; some configured URLs are credentials.
        logging.getLogger("httpx").setLevel(logging.WARNING)
        logging.getLogger("httpcore").setLevel(logging.WARNING)
        self.config = config
        self._sleep = sleep
        self._monotonic = monotonic
        self._last_request: dict[str, float] = {}
        self.requests = 0
        self._owned = client is None
        self._client = client or httpx.Client(
            timeout=httpx.Timeout(
                connect=config.connect_timeout,
                read=config.read_timeout,
                write=config.read_timeout,
                pool=config.connect_timeout,
            ),
            headers={"User-Agent": config.user_agent, "Accept": "application/json"},
            follow_redirects=True,
        )

    def close(self) -> None:
        if self._owned:
            self._client.close()

    def __enter__(self) -> "HttpClient":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def _pace(self, key: str, interval: float) -> None:
        if interval <= 0:
            return
        now = self._monotonic()
        previous = self._last_request.get(key)
        if previous is not None:
            remaining = interval - (now - previous)
            if remaining > 0:
                self._sleep(remaining)
        self._last_request[key] = self._monotonic()

    @staticmethod
    def _retry_after_value(value: str | None, ceiling: float = 120.0) -> float | None:
        """Parse a usable Retry-After, or return None for a missing or invalid one."""
        if not value:
            return None
        text = value.strip()
        if not text:
            return None
        try:
            number = float(text)
        except (TypeError, ValueError, OverflowError):
            number = None
        if number is not None:
            if not math.isfinite(number):
                return None
            return min(max(number, 0.0), ceiling)
        try:
            parsed = email.utils.parsedate_to_datetime(text)
        except (TypeError, ValueError, OverflowError):
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return min(
            max((parsed - datetime.now(timezone.utc)).total_seconds(), 0.0),
            ceiling,
        )

    @staticmethod
    def _retry_after(value: str | None, fallback: float, ceiling: float = 120.0) -> float:
        parsed = HttpClient._retry_after_value(value, ceiling)
        return fallback if parsed is None else parsed

    def request_json(
        self,
        method: str,
        url: str,
        *,
        source: str,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        data: Mapping[str, Any] | None = None,
        json: Any = None,
        minimum_interval: float = 0,
        expected: tuple[int, ...] = (200,),
        max_retries: int | None = None,
        decode_json: bool = True,
        throttle: Throttle | None = None,
    ) -> Any:
        last_error: Exception | None = None
        retry_count = self.config.retries if max_retries is None else max_retries
        requests_before = self.requests
        attempt = 0
        while True:
            self.requests += 1
            self._pace(source, minimum_interval)
            try:
                response = self._client.request(
                    method, url, params=params, headers=headers, data=data, json=json,
                    follow_redirects=False,
                )
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_error = exc
                if attempt >= retry_count:
                    break
                self._sleep(min(self.config.backoff_seconds * (2**attempt), 120))
                attempt += 1
                continue
            if response.status_code in expected:
                if not decode_json:
                    if throttle is not None:
                        throttle.succeeded = True
                    return None
                if response.status_code == 204 or not response.content:
                    if throttle is not None:
                        throttle.succeeded = True
                    return None
                try:
                    payload = response.json()
                except ValueError as exc:
                    raise SourceError(source, "source returned invalid JSON") from exc
                if throttle is not None:
                    throttle.succeeded = True
                return payload
            if (
                throttle is not None
                and response.status_code in THROTTLE_STATUS
                and throttle.succeeded
            ):
                retry_after = self._retry_after_value(
                    response.headers.get("Retry-After"),
                    throttle.maximum_delay,
                )
                if throttle.wait(retry_after):
                    continue
                raise SourceError(
                    source,
                    f"HTTP {response.status_code}",
                    status_code=response.status_code,
                    requests=self.requests - requests_before,
                )
            if response.status_code not in RETRYABLE_STATUS or attempt >= retry_count:
                # Upstream headers/reason phrases can echo secret URLs or tokens.
                raise SourceError(
                    source,
                    f"HTTP {response.status_code}",
                    status_code=response.status_code,
                    requests=attempt + 1,
                )
            delay = self.config.backoff_seconds * (2**attempt)
            self._sleep(self._retry_after(response.headers.get("Retry-After"), delay))
            attempt += 1
        failure_type = type(last_error).__name__ if last_error else "transport failure"
        raise SourceError(
            source,
            f"request failed after bounded retries ({failure_type})",
            requests=retry_count + 1,
        )

    def stream_bytes(
        self,
        url: str,
        *,
        source: str,
        byte_cap: int,
        params: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        minimum_interval: float = 0,
        counter: list[int] | None = None,
    ) -> Iterator[bytes]:
        """Stream a bounded response body without holding it in memory.

        Redirects are never followed and the compressed byte count is capped
        while reading, so an oversized file cannot be buffered first.
        """
        last_error: Exception | None = None
        retry_count = self.config.retries
        for attempt in range(retry_count + 1):
            self.requests += 1
            self._pace(source, minimum_interval)
            if counter is not None:
                counter[0] += 1
            yielded = False
            try:
                with self._client.stream(
                    "GET",
                    url,
                    params=params,
                    headers=headers,
                    follow_redirects=False,
                ) as response:
                    if response.status_code == 200:
                        total = 0
                        for chunk in response.iter_bytes():
                            total += len(chunk)
                            if total > byte_cap:
                                raise SourceError(
                                    source, "source response exceeded the size limit"
                                )
                            yielded = True
                            yield chunk
                        return
                    if (
                        response.status_code not in RETRYABLE_STATUS
                        or attempt >= retry_count
                    ):
                        raise SourceError(
                            source,
                            f"HTTP {response.status_code}",
                            status_code=response.status_code,
                            requests=counter[0] if counter is not None else 0,
                        )
                    retry_after = response.headers.get("Retry-After")
            except (httpx.TimeoutException, httpx.TransportError) as exc:
                last_error = exc
                if yielded:
                    raise SourceError(
                        source,
                        f"request failed after a partial response ({type(exc).__name__})",
                        requests=counter[0] if counter is not None else 0,
                    ) from exc
                if attempt >= retry_count:
                    break
                self._sleep(min(self.config.backoff_seconds * (2**attempt), 120))
                continue
            self._sleep(
                self._retry_after(
                    retry_after, self.config.backoff_seconds * (2**attempt)
                )
            )
        failure_type = type(last_error).__name__ if last_error else "transport failure"
        raise SourceError(
            source,
            f"request failed after bounded retries ({failure_type})",
            requests=counter[0] if counter is not None else 0,
        )

    def get_json(self, url: str, **kwargs: Any) -> Any:
        return self.request_json("GET", url, **kwargs)

    def post_json(self, url: str, **kwargs: Any) -> Any:
        return self.request_json("POST", url, **kwargs)

    def request_once(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, Any] | None = None,
        data: Mapping[str, Any] | None = None,
        json: Any = None,
        content: bytes | str | None = None,
        timeout: float | None = None,
        body_limit: int = 65536,
    ) -> HttpResult:
        """Send one request without retries and without following redirects.

        Delivery code classifies transport failures itself: a connect failure
        is definitely unsent, while a read failure may follow an accepted
        request. The response body is bounded, is never included in an error,
        and is read only until the per-send wall-clock deadline.
        """
        if body_limit < 0:
            raise ValueError("body limit must not be negative")
        self.requests += 1
        started = self._monotonic()
        request_headers = dict(headers or {})
        # Count wire bytes rather than an expanded compressed body.
        request_headers["Accept-Encoding"] = "identity"
        request = self._client.build_request(
            method,
            url,
            headers=request_headers,
            params=params,
            data=data,
            json=json,
            content=content,
            timeout=timeout,
        )
        response = self._client.send(request, follow_redirects=False, stream=True)
        try:
            status_code = response.status_code
            body = bytearray()
            try:
                # A test transport may hand back an already-read response;
                # real sends stay on the raw stream so ``body_limit`` counts
                # wire bytes rather than decoded content.
                chunks = (
                    response.iter_bytes()
                    if response.is_stream_consumed
                    else response.iter_raw()
                )
                for chunk in chunks:
                    if timeout is not None and self._monotonic() - started > timeout:
                        break
                    remaining = body_limit - len(body)
                    if remaining <= 0:
                        break
                    body.extend(chunk[:remaining])
            except (httpx.TimeoutException, httpx.TransportError):
                # The status line arrived, so the request was accepted even if
                # the optional response body was not read completely.
                pass
            return HttpResult(status_code, dict(response.headers), bytes(body))
        finally:
            response.close()
