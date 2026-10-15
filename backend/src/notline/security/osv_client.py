from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from notline.security.osv_models import OsvAdvisory

JsonPayload = dict[str, Any]
JsonRequester = Callable[[JsonPayload], JsonPayload]


class OsvClientError(RuntimeError):
    """Raised when an OSV request cannot be completed or parsed."""


class OsvClient:
    """Small cached client for exact package-version OSV queries."""

    def __init__(
        self,
        *,
        base_url: str = "https://api.osv.dev/v1",
        timeout_seconds: float = 30.0,
        retry_count: int = 2,
        cache_dir: Path | None = None,
        cache_ttl_seconds: float = 86_400.0,
        request_json: JsonRequester | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if retry_count < 0:
            raise ValueError("retry_count cannot be negative")
        if cache_ttl_seconds < 0:
            raise ValueError("cache_ttl_seconds cannot be negative")

        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds
        self._retry_count = retry_count
        self._cache_dir = cache_dir
        self._cache_ttl_seconds = cache_ttl_seconds
        self._request_json = request_json or self._request_over_network
        self._sleep = sleep
        self._clock = clock

    def query_package(
        self,
        *,
        ecosystem: str,
        name: str,
        version: str,
    ) -> list[OsvAdvisory]:
        """Return advisories affecting this exact package version."""

        payload = {
            "package": {"ecosystem": ecosystem, "name": name},
            "version": version,
        }
        response = self._get_json(payload)
        raw_vulnerabilities = response.get("vulns", [])
        if not isinstance(raw_vulnerabilities, list):
            raise OsvClientError("OSV response field 'vulns' is not a list")
        return [
            OsvAdvisory.from_osv(vulnerability)
            for vulnerability in raw_vulnerabilities
            if isinstance(vulnerability, dict) and vulnerability.get("id")
        ]

    def _get_json(self, payload: JsonPayload) -> JsonPayload:
        cached = self._read_cache(payload)
        if cached is not None:
            return cached

        for attempt in range(self._retry_count + 1):
            try:
                response = self._request_json(payload)
            except (HTTPError, URLError):
                if attempt >= self._retry_count:
                    raise OsvClientError("OSV request failed") from None
                self._sleep(2.0**attempt)
                continue

            self._write_cache(payload, response)
            return response

        raise OsvClientError("OSV request failed after retries")

    def _request_over_network(
        self,
        payload: JsonPayload,
    ) -> JsonPayload:
        request = Request(
            f"{self._base_url}/query",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "notline-security-twin/0.1",
            },
            method="POST",
        )
        with urlopen(request, timeout=self._timeout_seconds) as response:
            result = json.load(response)

        if not isinstance(result, dict):
            raise OsvClientError("OSV response is not a JSON object")
        return result

    def _cache_path(self, payload: JsonPayload) -> Path | None:
        if self._cache_dir is None:
            return None
        cache_key = hashlib.sha256(
            json.dumps(
                payload,
                sort_keys=True,
            ).encode("utf-8")
        ).hexdigest()
        return self._cache_dir / f"{cache_key}.json"

    def _read_cache(
        self,
        payload: JsonPayload,
    ) -> JsonPayload | None:
        path = self._cache_path(payload)
        if path is None or not path.exists():
            return None

        try:
            cached = json.loads(path.read_text(encoding="utf-8"))
            fetched_at = float(cached["fetched_at"])
            response = cached["response"]
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            return None

        if self._clock() - fetched_at > self._cache_ttl_seconds:
            return None
        return response if isinstance(response, dict) else None

    def _write_cache(
        self,
        payload: JsonPayload,
        response: JsonPayload,
    ) -> None:
        path = self._cache_path(payload)
        if path is None:
            return

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {"fetched_at": self._clock(), "response": response},
                sort_keys=True,
            ),
            encoding="utf-8",
        )
