"""Shared fixtures: an offline fake internet and a scan-friendly config.

Every test in this suite runs without touching the network. Sources are
exercised through ``httpx.MockTransport`` so the *real* engine code path runs —
robots handling, retries, detectors, reports — while the bytes come from a
route table.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

import httpx
import pytest

from d3ta1l3r.config import RateLimitConfig, ScanConfig
from d3ta1l3r.core.cache import ResponseCache
from d3ta1l3r.core.http import Fetcher
from d3ta1l3r.core.ratelimit import HostRateLimiter
from d3ta1l3r.core.robots import RobotsPolicy

__all__ = ["RouteTable", "html", "json_response", "make_config", "mock_transport", "text"]

ResponseSpec = Any


def html(body: str, status: int = 200) -> tuple[int, str, dict[str, str]]:
    return status, body, {"content-type": "text/html; charset=utf-8"}


def text(body: str, status: int = 200) -> tuple[int, str, dict[str, str]]:
    return status, body, {"content-type": "text/plain; charset=utf-8"}


def json_response(payload: Any, status: int = 200) -> tuple[int, str, dict[str, str]]:
    return status, json.dumps(payload), {"content-type": "application/json"}


def make_config(**overrides: Any) -> ScanConfig:
    """A config tuned for tests: fast, offline-friendly, still polite in shape."""
    rate_overrides = overrides.pop("rate", {}) or {}
    rate = RateLimitConfig(
        per_host_rps=rate_overrides.pop("per_host_rps", 10_000.0),
        per_host_burst=rate_overrides.pop("per_host_burst", 1_000),
        global_concurrency=rate_overrides.pop("global_concurrency", 8),
        max_retries=rate_overrides.pop("max_retries", 0),
        backoff_base=rate_overrides.pop("backoff_base", 0.0),
        backoff_max=rate_overrides.pop("backoff_max", 0.0),
        **rate_overrides,
    )
    values: dict[str, Any] = {
        "strict_ssrf": False,  # MockTransport hosts are fake by construction
        "respect_robots": True,
        "timeout": 5.0,
        "connect_timeout": 2.0,
        "rate": rate,
    }
    values.update(overrides)
    return ScanConfig(**values)


@dataclass
class RouteTable:
    """URL-substring → response mapping, with a default for robots.txt and misses."""

    routes: dict[str, ResponseSpec]
    robots_status: int = 404
    robots_body: str = ""
    default: ResponseSpec = 404
    calls: list[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        self.calls = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.calls.append(url)
        if url.endswith("/robots.txt"):
            return _build(httpx.Response(self.robots_status, text=self.robots_body), request)
        for needle in sorted(self.routes, key=len, reverse=True):
            if needle in url:
                return _build(self.routes[needle], request)
        return _build(self.default, request)

    def count(self, needle: str) -> int:
        return sum(1 for url in self.calls if needle in url)


def _build(spec: ResponseSpec, request: httpx.Request) -> httpx.Response:
    if callable(spec):
        response = spec(request)
        response.request = request
        return response
    if isinstance(spec, httpx.Response):
        spec.request = request
        return spec
    if isinstance(spec, tuple):
        status, body, *rest = spec
        headers = rest[0] if rest else {}
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
            headers = {"content-type": "application/json", **headers}
        return httpx.Response(status, text=str(body), headers=headers, request=request)
    if isinstance(spec, int):
        return httpx.Response(spec, request=request, text="")
    return httpx.Response(200, text=str(spec), request=request)


def mock_transport(
    routes: Mapping[str, ResponseSpec] | None = None,
    *,
    robots_status: int = 404,
    robots_body: str = "",
    default: ResponseSpec = 404,
) -> tuple[httpx.MockTransport, RouteTable]:
    table = RouteTable(dict(routes or {}), robots_status=robots_status,
                       robots_body=robots_body, default=default)
    return httpx.MockTransport(table.handler), table


async def build_fetcher(
    routes: Mapping[str, ResponseSpec] | None = None,
    *,
    config: ScanConfig | None = None,
    robots: bool = False,
    cache: ResponseCache | None = None,
    **transport_kwargs: Any,
) -> tuple[Fetcher, RouteTable]:
    """A started :class:`Fetcher` wired to a route table."""
    transport, table = mock_transport(routes, **transport_kwargs)
    fetcher = Fetcher(config or make_config(), transport=transport, cache=cache,
                      limiter=HostRateLimiter(10_000.0, 1_000))
    await fetcher.start()
    if robots:
        fetcher.robots = RobotsPolicy(fetcher)
    return fetcher, table


@pytest.fixture
def config() -> ScanConfig:
    return make_config()


@pytest.fixture
async def fetcher_factory():
    """Async factory returning ``(fetcher, route_table)``; closes clients afterwards."""
    created: list[Fetcher] = []

    async def factory(routes=None, **kwargs):
        fetcher, table = await build_fetcher(routes, **kwargs)
        created.append(fetcher)
        return fetcher, table

    yield factory

    for fetcher in created:
        await fetcher.close()


def pytest_collection_modifyitems(config: pytest.Config, items: Iterable[pytest.Item]) -> None:
    """Skip anything marked ``network`` unless the operator opts in explicitly."""
    if config.getoption("-m") and "network" in config.getoption("-m"):
        return
    skip = pytest.mark.skip(reason="network test (run with -m network)")
    for item in items:
        if "network" in item.keywords:
            item.add_marker(skip)


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "network: performs real outbound HTTP requests")


@pytest.fixture(autouse=True)
def no_local_model_daemons(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep backend probes from finding a real daemon on the test machine.

    :func:`~d3ta1l3r.llm.backends.select_backend` discovers models by asking
    Ollama on ``127.0.0.1:11434`` and Cortex on ``127.0.0.1:8624`` what they
    have. That makes any test asserting "with no model installed, the answer
    comes from retrieval" depend on what happens to be running: it passes on a
    bare machine and fails on a developer's laptop with Ollama installed, and
    on a machine with neither it waits for a TCP refusal.

    So a backend built *without* a transport — i.e. one that would really dial
    out — gets a transport that refuses instantly, which is the same outcome as
    a machine with no daemon, arrived at without a socket. Tests that supply
    their own ``transport=`` are untouched and still exercise the real code.
    """
    from d3ta1l3r.llm import backends

    original = {
        backends.OllamaBackend: backends.OllamaBackend._client,
        backends.CortexBackend: backends.CortexBackend._client,
    }

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no daemon during tests", request=request)

    def _make_offline(cls: Any) -> Any:
        real = original[cls]

        def _client(self: Any) -> httpx.Client:
            if self._transport is not None:
                return real(self)
            return httpx.Client(
                base_url=self.host, timeout=1.0, transport=httpx.MockTransport(refuse)
            )

        return _client

    for cls in original:
        monkeypatch.setattr(cls, "_client", _make_offline(cls))
