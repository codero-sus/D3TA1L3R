"""Cortex LLM Hoster backend: local-first, OpenAI wire format, LAN by request only.

Cortex serves a GGUF you own at ``/v1/chat/completions``, so the payload shape is
the one OpenAI popularised while the privacy story is unchanged from Ollama's:
the model is on your machine. The one new decision is the host rule — a private
LAN box is allowed *if you name it*, a public address never is — and most of the
tests below exist to keep that rule honest rather than to re-test httpx.

Everything is stubbed with ``MockTransport``: no test here touches a network.
"""

from __future__ import annotations

import httpx
import pytest

from d3ta1l3r.errors import UsageError
from d3ta1l3r.llm.backends import (
    CORTEX_API_KEY_ENV,
    CORTEX_DEFAULT_HOST,
    CortexBackend,
    is_private_lan_host,
)


def _handler_for(
    *,
    models: list[str] | None = None,
    reply: str = "It is on example.com.",
    status: int = 200,
    models_status: int = 200,
) -> httpx.MockTransport:
    """A stub Cortex: ``/v1/models`` lists models, ``/v1/chat/completions`` replies."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/models":
            if models_status != 200:
                return httpx.Response(models_status, json={"error": "nope"})
            return httpx.Response(200, json={"data": [{"id": name} for name in models or []]})
        if request.url.path == "/v1/chat/completions":
            if status != 200:
                return httpx.Response(status, json={"error": "nope"})
            return httpx.Response(
                200,
                json={"choices": [{"message": {"role": "assistant", "content": reply}}]},
            )
        return httpx.Response(404, json={"error": "unknown route"})

    return httpx.MockTransport(handler)


# ---------------------------------------------------------------------------
class TestHostPolicy:
    """Loopback always; private LAN only when named; public never."""

    def test_loopback_is_the_default(self) -> None:
        backend = CortexBackend()
        assert backend.host == "http://127.0.0.1:8624"
        assert backend.on_lan is False

    def test_a_public_ip_is_refused(self) -> None:
        with pytest.raises(UsageError, match="refuses the non-local host"):
            CortexBackend(host="http://203.0.113.5:8624")

    def test_a_public_name_is_refused(self) -> None:
        with pytest.raises(UsageError, match="refuses the non-local host"):
            CortexBackend(host="http://cortex.example.com:8624")

    def test_a_public_host_is_refused_even_when_lan_is_allowed(self) -> None:
        """allow_lan widens the rule to your own network, not to the internet."""
        with pytest.raises(UsageError, match="refuses the non-local host"):
            CortexBackend(host="http://203.0.113.5:8624", allow_lan=True)

    @pytest.mark.parametrize("host", ["http://10.1.2.3:8624", "http://192.168.1.9:8624",
                                      "http://172.16.0.4:8624"])
    def test_a_private_lan_host_needs_to_be_named(self, host: str) -> None:
        with pytest.raises(UsageError, match="--cortex-host"):
            CortexBackend(host=host)

    @pytest.mark.parametrize("host", ["http://10.1.2.3:8624", "http://192.168.1.9:8624",
                                      "http://172.16.0.4:8624"])
    def test_a_named_private_lan_host_is_accepted(self, host: str) -> None:
        # Stubbed transport: describe() probes, and this suite makes no network calls.
        backend = CortexBackend(host=host, allow_lan=True, transport=_handler_for(models=["m"]))
        assert backend.on_lan is True
        assert backend.describe()["on_lan"] is True
        assert backend.describe()["local_only"] is False

    def test_loopback_is_never_reported_as_lan(self) -> None:
        backend = CortexBackend(transport=_handler_for(models=["m"]))
        assert backend.describe()["local_only"] is True
        assert backend.describe()["on_lan"] is False


class TestIsPrivateLanHost:
    @pytest.mark.parametrize(
        "host",
        ["10.0.0.1", "10.255.255.254", "192.168.0.1", "172.16.0.1", "172.31.255.254"],
    )
    def test_rfc1918_is_lan(self, host: str) -> None:
        assert is_private_lan_host(host) is True

    @pytest.mark.parametrize(
        "host",
        ["127.0.0.1", "::1", "203.0.113.5", "8.8.8.8", "172.32.0.1", "example.com", ""],
    )
    def test_everything_else_is_not(self, host: str) -> None:
        assert is_private_lan_host(host) is False

    @pytest.mark.parametrize("host", ["203.0.113.5", "198.51.100.7", "100.64.0.1",
                                      "169.254.1.1", "192.0.2.9"])
    def test_reserved_but_not_rfc1918_is_not_lan(self, host: str) -> None:
        """`ipaddress.is_private` covers these; a home LAN does not.

        203.0.113/24 and 198.51.100/24 are documentation ranges, 100.64/10 is
        carrier NAT, 169.254/16 is link-local. Treating any of them as "my
        network" would let a public address through the host rule.
        """
        assert is_private_lan_host(host) is False

    def test_a_port_and_scheme_are_stripped(self) -> None:
        assert is_private_lan_host("http://192.168.50.7:8624") is True

    def test_a_hostname_is_not_resolved(self) -> None:
        """A name could resolve anywhere, so it is never accepted as LAN."""
        assert is_private_lan_host("cortex.lan") is False

    def test_loopback_is_not_counted_as_lan(self) -> None:
        """127.0.0.1 is technically private; here it has its own, stricter rule."""
        assert is_private_lan_host("127.0.0.1") is False


# ---------------------------------------------------------------------------
class TestAvailability:
    def test_auto_picks_the_first_served_model(self) -> None:
        transport = _handler_for(models=["qwen-local", "phi-local"])
        backend = CortexBackend(transport=transport)
        ok, reason = backend.available()
        assert ok is True
        assert backend.model_id == "qwen-local"
        assert "auto-picked qwen-local" in reason

    def test_an_explicit_model_is_used_when_served(self) -> None:
        transport = _handler_for(models=["qwen-local", "phi-local"])
        backend = CortexBackend("phi-local", transport=transport)
        assert backend.available()[0] is True
        assert backend.model_id == "phi-local"

    def test_a_model_cortex_does_not_serve_is_a_failure(self) -> None:
        transport = _handler_for(models=["qwen-local"])
        backend = CortexBackend("nope", transport=transport)
        ok, reason = backend.available()
        assert ok is False
        assert "does not serve nope" in reason
        assert "qwen-local" in reason, "the available models should be offered"

    def test_running_but_empty_is_unavailable(self) -> None:
        backend = CortexBackend(transport=_handler_for(models=[]))
        ok, reason = backend.available()
        assert ok is False
        assert "serves no models" in reason

    def test_no_server_is_unavailable(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=request)

        backend = CortexBackend(transport=httpx.MockTransport(handler))
        ok, reason = backend.available()
        assert ok is False
        assert "no Cortex server at" in reason

    def test_a_bearer_key_request_is_explained(self) -> None:
        backend = CortexBackend(transport=_handler_for(models_status=401))
        ok, reason = backend.available()
        assert ok is False
        assert CORTEX_API_KEY_ENV in reason

    def test_an_unreadable_models_list_is_a_failure(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text="<html>not json</html>")

        backend = CortexBackend(transport=httpx.MockTransport(handler))
        ok, _ = backend.available()
        assert ok is False

    def test_served_models_is_reported(self) -> None:
        backend = CortexBackend(transport=_handler_for(models=["a-local", "b-local"]))
        assert backend.served_models() == ["a-local", "b-local"]


# ---------------------------------------------------------------------------
class TestGeneration:
    def test_the_answer_is_read_from_the_openai_envelope(self) -> None:
        transport = _handler_for(models=["qwen-local"], reply="Two findings mention it.")
        backend = CortexBackend(transport=transport)
        assert backend.generate([{"role": "user", "content": "hi"}]) == "Two findings mention it."

    def test_the_resolved_model_is_what_gets_sent(self) -> None:
        """``auto`` must not put the literal string 'auto' in the request body."""
        seen: list[dict[str, object]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            import json

            if request.url.path == "/v1/models":
                return httpx.Response(200, json={"data": [{"id": "qwen-local"}]})
            seen.append(json.loads(request.content))
            return httpx.Response(
                200, json={"choices": [{"message": {"content": "ok"}}]}
            )

        backend = CortexBackend(transport=httpx.MockTransport(handler))
        backend.generate([{"role": "user", "content": "hi"}])
        assert seen, "the chat route should have been called"
        assert seen[0]["model"] == "qwen-local"

    def test_generation_resolves_the_model_first(self) -> None:
        """Calling generate() cold must still send a real model name."""
        transport = _handler_for(models=["only-model"], reply="ok")
        assert CortexBackend(transport=transport).generate([{"role": "user", "content": "?"}]) == "ok"

    def test_the_key_from_the_environment_is_sent_as_a_bearer_token(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv(CORTEX_API_KEY_ENV, "cortex-secret")
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/v1/models":
                return httpx.Response(200, json={"data": [{"id": "qwen-local"}]})
            seen.append(request.headers.get("authorization", ""))
            return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

        CortexBackend(transport=httpx.MockTransport(handler)).generate(
            [{"role": "user", "content": "hi"}]
        )
        assert seen == ["Bearer cortex-secret"]

    def test_no_key_means_no_authorization_header(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv(CORTEX_API_KEY_ENV, raising=False)
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/v1/models":
                return httpx.Response(200, json={"data": [{"id": "qwen-local"}]})
            seen.append(request.headers.get("authorization", ""))
            return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

        CortexBackend(transport=httpx.MockTransport(handler)).generate(
            [{"role": "user", "content": "hi"}]
        )
        assert seen == [""]

    def test_streaming_is_turned_off(self) -> None:
        """A streamed response would need SSE parsing we do not do."""
        seen: list[dict[str, object]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            import json

            if request.url.path == "/v1/models":
                return httpx.Response(200, json={"data": [{"id": "qwen-local"}]})
            seen.append(json.loads(request.content))
            return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

        CortexBackend(transport=httpx.MockTransport(handler)).generate(
            [{"role": "user", "content": "hi"}]
        )
        assert seen[0]["stream"] is False

    def test_a_401_while_generating_names_the_key_variable(self) -> None:
        backend = CortexBackend(transport=_handler_for(models=["qwen-local"], status=401))
        with pytest.raises(UsageError, match=CORTEX_API_KEY_ENV):
            backend.generate([{"role": "user", "content": "hi"}])

    def test_a_server_error_is_reported(self) -> None:
        backend = CortexBackend(transport=_handler_for(models=["qwen-local"], status=503))
        with pytest.raises(UsageError, match="Cortex answered 503"):
            backend.generate([{"role": "user", "content": "hi"}])

    def test_an_empty_answer_is_an_error(self) -> None:
        backend = CortexBackend(transport=_handler_for(models=["qwen-local"], reply="   "))
        with pytest.raises(UsageError, match="empty answer"):
            backend.generate([{"role": "user", "content": "hi"}])

    def test_no_choices_is_an_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/v1/models":
                return httpx.Response(200, json={"data": [{"id": "qwen-local"}]})
            return httpx.Response(200, json={"choices": []})

        backend = CortexBackend(transport=httpx.MockTransport(handler))
        with pytest.raises(UsageError, match="no choices"):
            backend.generate([{"role": "user", "content": "hi"}])

    def test_an_unavailable_backend_refuses_to_generate(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=request)

        backend = CortexBackend(transport=httpx.MockTransport(handler))
        with pytest.raises(UsageError, match="Cortex cannot answer"):
            backend.generate([{"role": "user", "content": "hi"}])


# ---------------------------------------------------------------------------
class TestRegistry:
    def test_cortex_is_a_selectable_backend(self) -> None:
        from d3ta1l3r.llm.backends import BACKENDS

        assert "cortex" in BACKENDS

    def test_cortex_counts_as_a_real_model(self) -> None:
        """Verification refuses to run on a non-model; Cortex is a model."""
        assert CortexBackend.is_model is True

    def test_the_default_host_stays_on_loopback(self) -> None:
        assert CORTEX_DEFAULT_HOST.startswith("http://127.0.0.1:")
