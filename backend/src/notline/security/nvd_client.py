from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from notline.security.models import (
    NvdCpeMatchCriterion,
    NvdCpeName,
    NvdCveRecord,
)

JsonPayload = dict[str, Any]
JsonRequester = Callable[[str, Mapping[str, str]], JsonPayload]


class NvdClientError(RuntimeError):
    """Raised when an NVD request cannot be completed or parsed."""


class NvdClient:
    """Small, rate-aware client for the NVD 2.0 JSON APIs."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str = "https://services.nvd.nist.gov/rest/json",
        timeout_seconds: float = 30.0,
        min_interval_seconds: float = 6.0,
        retry_count: int = 2,
        cache_dir: Path | None = None,
        cache_ttl_seconds: float = 86_400.0,
        request_json: JsonRequester | None = None,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if min_interval_seconds < 0:
            raise ValueError("min_interval_seconds cannot be negative")
        if retry_count < 0:
            raise ValueError("retry_count cannot be negative")
        if cache_ttl_seconds < 0:
            raise ValueError("cache_ttl_seconds cannot be negative")

        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds
        self._min_interval_seconds = min_interval_seconds
        self._retry_count = retry_count
        self._cache_dir = cache_dir
        self._cache_ttl_seconds = cache_ttl_seconds
        self._request_json = request_json or self._request_over_network
        self._sleep = sleep
        self._monotonic = monotonic
        self._clock = clock
        self._last_request_at: float | None = None

    def search_cpes(
        self,
        keyword: str,
        *,
        max_results: int = 100,
        page_size: int = 100,
    ) -> list[NvdCpeName]:
        """Search the NVD CPE dictionary, returning non-deprecated entries."""

        raw_entries = self._fetch_pages(
            endpoint="/cpes/2.0",
            params={"keywordSearch": keyword},
            result_key="products",
            max_results=max_results,
            page_size=page_size,
        )
        return [
            NvdCpeName.from_nvd(entry["cpe"])
            for entry in raw_entries
            if not entry["cpe"].get("deprecated", False)
        ]

    def fetch_cves_for_cpe(
        self,
        cpe_name: str,
        *,
        page_size: int = 200,
    ) -> list[NvdCveRecord]:
        """Fetch and normalize all CVEs associated with one exact CPE name."""

        raw_entries = self._fetch_pages(
            endpoint="/cves/2.0",
            params={"cpeName": cpe_name},
            result_key="vulnerabilities",
            max_results=None,
            page_size=page_size,
        )
        return [NvdCveRecord.from_nvd(entry) for entry in raw_entries]

    def search_cpe_match_criteria(
        self,
        match_string: str,
        *,
        max_results: int = 100,
        page_size: int = 100,
    ) -> list[NvdCpeMatchCriterion]:
        """Search active NVD CPE version-range criteria."""

        raw_entries = self._fetch_pages(
            endpoint="/cpematch/2.0",
            params={"matchStringSearch": match_string},
            result_key="matchStrings",
            max_results=max_results,
            page_size=page_size,
        )
        criteria = [NvdCpeMatchCriterion.from_nvd(entry) for entry in raw_entries]
        return [criterion for criterion in criteria if criterion.status == "Active"]

    def _fetch_pages(
        self,
        *,
        endpoint: str,
        params: Mapping[str, str],
        result_key: str,
        max_results: int | None,
        page_size: int,
    ) -> list[JsonPayload]:
        if page_size < 1 or page_size > 2_000:
            raise ValueError("page_size must be between 1 and 2000")
        if max_results is not None and max_results < 1:
            raise ValueError("max_results must be positive")

        entries: list[JsonPayload] = []
        start_index = 0

        while max_results is None or len(entries) < max_results:
            page_params = dict(params)
            page_params["startIndex"] = str(start_index)
            page_params["resultsPerPage"] = str(page_size)
            payload = self._get_json(endpoint, page_params)
            page = payload.get(result_key, [])
            if not isinstance(page, list):
                raise NvdClientError(f"NVD response field {result_key!r} is not a list")

            entries.extend(entry for entry in page if isinstance(entry, dict))
            total_results = int(payload.get("totalResults", len(entries)))
            start_index += len(page)

            if not page or start_index >= total_results:
                break

        return entries if max_results is None else entries[:max_results]

    def _get_json(
        self,
        endpoint: str,
        params: Mapping[str, str],
    ) -> JsonPayload:
        cached = self._read_cache(endpoint, params)
        if cached is not None:
            return cached

        for attempt in range(self._retry_count + 1):
            self._wait_for_rate_limit()
            try:
                payload = self._request_json(endpoint, params)
            except (HTTPError, URLError) as error:
                if not self._is_retryable(error) or attempt >= self._retry_count:
                    raise NvdClientError("NVD request failed") from error
                self._sleep(2.0**attempt)
                continue

            self._write_cache(endpoint, params, payload)
            return payload

        raise NvdClientError("NVD request failed after retries")

    def _request_over_network(
        self,
        endpoint: str,
        params: Mapping[str, str],
    ) -> JsonPayload:
        url = f"{self._base_url}{endpoint}?{urlencode(params)}"
        headers = {
            "Accept": "application/json",
            "User-Agent": "notline-security-twin/0.1",
        }
        if self._api_key:
            headers["apiKey"] = self._api_key

        request = Request(url, headers=headers)
        with urlopen(request, timeout=self._timeout_seconds) as response:
            payload = json.load(response)

        if not isinstance(payload, dict):
            raise NvdClientError("NVD response is not a JSON object")
        return payload

    def _wait_for_rate_limit(self) -> None:
        now = self._monotonic()
        if self._last_request_at is not None:
            elapsed = now - self._last_request_at
            remaining = self._min_interval_seconds - elapsed
            if remaining > 0:
                self._sleep(remaining)
        self._last_request_at = self._monotonic()

    def _is_retryable(self, error: HTTPError | URLError) -> bool:
        return isinstance(error, URLError) or (
            isinstance(error, HTTPError) and error.code in {429, 500, 502, 503, 504}
        )

    def _cache_path(
        self,
        endpoint: str,
        params: Mapping[str, str],
    ) -> Path | None:
        if self._cache_dir is None:
            return None
        cache_key = hashlib.sha256(
            f"{endpoint}?{urlencode(sorted(params.items()))}".encode()
        ).hexdigest()
        return self._cache_dir / f"{cache_key}.json"

    def _read_cache(
        self,
        endpoint: str,
        params: Mapping[str, str],
    ) -> JsonPayload | None:
        path = self._cache_path(endpoint, params)
        if path is None or not path.exists():
            return None

        try:
            cached = json.loads(path.read_text(encoding="utf-8"))
            fetched_at = float(cached["fetched_at"])
            payload = cached["payload"]
        except (OSError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            return None

        if self._clock() - fetched_at > self._cache_ttl_seconds:
            return None
        return payload if isinstance(payload, dict) else None

    def _write_cache(
        self,
        endpoint: str,
        params: Mapping[str, str],
        payload: JsonPayload,
    ) -> None:
        path = self._cache_path(endpoint, params)
        if path is None:
            return

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {"fetched_at": self._clock(), "payload": payload},
                sort_keys=True,
            ),
            encoding="utf-8",
        )
