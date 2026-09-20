"""Bounded HTTP transport shared by all remote-source adapters."""

from __future__ import annotations

import email.utils
import logging
import math
import time
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from typing import Any

import httpx

from .config import HttpConfig
from .errors import SourceError

RETRYABLE_STATUS = {429, 500, 502, 503, 504}


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
    def _retry_after(value: str | None, fallback: float, ceiling: float = 120.0) -> float:
        if value:
            try:
                number = float(value)
                if math.isfinite(number):
                    return min(max(number, 0), ceiling)
            except ValueError:
                try:
                    parsed = email.utils.parsedate_to_datetime(value)
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=timezone.utc)
                    return min(max((parsed - datetime.now(timezone.utc)).total_seconds(), 0), ceiling)
                except (TypeError, ValueError, OverflowError):
                    pass
        return min(fallback, ceiling)

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
    ) -> Any:
        last_error: Exception | None = None
        retry_count = self.config.retries if max_retries is None else max_retries
        for attempt in range(retry_count + 1):
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
                continue
            if response.status_code in expected:
                if not decode_json:
                    return None
                if response.status_code == 204 or not response.content:
                    return None
                try:
                    return response.json()
                except ValueError as exc:
                    raise SourceError(source, "source returned invalid JSON") from exc
            if response.status_code not in RETRYABLE_STATUS or attempt >= retry_count:
                # Upstream headers/reason phrases can echo secret URLs or tokens.
                raise SourceError(source, f"HTTP {response.status_code}")
            delay = self.config.backoff_seconds * (2**attempt)
            self._sleep(self._retry_after(response.headers.get("Retry-After"), delay))
        failure_type = type(last_error).__name__ if last_error else "transport failure"
        raise SourceError(source, f"request failed after bounded retries ({failure_type})")

    def get_json(self, url: str, **kwargs: Any) -> Any:
        return self.request_json("GET", url, **kwargs)

    def post_json(self, url: str, **kwargs: Any) -> Any:
        return self.request_json("POST", url, **kwargs)
