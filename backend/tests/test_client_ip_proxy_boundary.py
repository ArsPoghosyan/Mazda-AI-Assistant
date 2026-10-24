"""Client-IP behavior through Uvicorn's real, in-process middleware stack."""

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from uvicorn import Config

from app.client_ip import ClientIPUnavailable, get_client_ip


@pytest.fixture(autouse=True)
def clear_proxy_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("FORWARDED_ALLOW_IPS", raising=False)


def make_client(
    peer: str,
    *,
    proxy_headers: bool,
    forwarded_allow_ips: str | None = None,
) -> TestClient:
    # This probe exists only in tests, not in the application router.
    application = FastAPI()

    @application.get("/probe")
    async def probe(request: Request) -> dict[str, str]:
        return {"client_ip": get_client_ip(request), "scheme": request.url.scheme}

    configuration = Config(
        application,
        proxy_headers=proxy_headers,
        forwarded_allow_ips=forwarded_allow_ips,
        interface="asgi3",
        http="h11",
        ws="none",
        log_config=None,
    )
    configuration.load()
    return TestClient(configuration.loaded_app, client=(peer, 12345))


@pytest.mark.parametrize("peer", ["127.0.0.1", "::1"])
@pytest.mark.parametrize(
    "headers",
    [
        [("X-Forwarded-For", "198.51.100.20")],
        [("X-Forwarded-For", "198.51.100.20, 203.0.113.30")],
        [("X-Forwarded-For", "198.51.100.20"), ("X-Forwarded-For", "203.0.113.30")],
        [("X-Forwarded-For", "invalid-address")],
        [
            ("X-Forwarded-For", "198.51.100.20"),
            ("X-Forwarded-Proto", "https"),
            ("Forwarded", "for=203.0.113.30;proto=https"),
            ("CF-Connecting-IP", "203.0.113.30"),
        ],
    ],
)
def test_disabled_proxy_headers_preserve_the_peer_even_with_wildcard_trust(
    peer: str, headers: list[tuple[str, str]]
) -> None:
    with make_client(peer, proxy_headers=False, forwarded_allow_ips="*") as client:
        response = client.get("/probe", headers=headers)

    assert response.status_code == 200
    assert response.json() == {"client_ip": peer, "scheme": "http"}


@pytest.mark.parametrize("peer", ["127.0.0.1", "::1"])
def test_enabled_proxy_headers_can_rewrite_the_address_before_the_helper(peer: str) -> None:
    with make_client(peer, proxy_headers=True, forwarded_allow_ips="127.0.0.1,::1") as client:
        response = client.get(
            "/probe",
            headers={"X-Forwarded-For": "198.51.100.20", "X-Forwarded-Proto": "https"},
        )

    assert response.json() == {"client_ip": "198.51.100.20", "scheme": "https"}


@pytest.mark.parametrize("peer", ["192.0.2.12", "2001:db8::12"])
def test_enabled_headers_from_an_untrusted_peer_are_ignored(peer: str) -> None:
    with make_client(peer, proxy_headers=True, forwarded_allow_ips="127.0.0.1,::1") as client:
        response = client.get(
            "/probe",
            headers={"X-Forwarded-For": "198.51.100.20", "X-Forwarded-Proto": "https"},
        )

    assert response.json() == {"client_ip": peer, "scheme": "http"}


@pytest.mark.parametrize(
    "headers",
    [
        [("X-Forwarded-For", "198.51.100.66, 203.0.113.12, 10.0.0.2")],
        [
            ("X-Forwarded-For", "198.51.100.66"),
            ("X-Forwarded-For", "203.0.113.12, 10.0.0.2"),
        ],
    ],
)
def test_trusted_proxy_chain_stops_at_the_nearest_untrusted_address(
    headers: list[tuple[str, str]],
) -> None:
    with make_client(
        "127.0.0.1", proxy_headers=True, forwarded_allow_ips="127.0.0.1,10.0.0.0/8"
    ) as client:
        response = client.get("/probe", headers=headers)

    assert response.json()["client_ip"] == "203.0.113.12"


def test_disabled_proxy_processing_overrides_a_permissive_environment_setting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "*")

    with make_client("127.0.0.1", proxy_headers=False) as client:
        response = client.get("/probe", headers={"X-Forwarded-For": "198.51.100.20"})

    assert response.json()["client_ip"] == "127.0.0.1"


def test_missing_forwarding_headers_leave_the_peer_unchanged() -> None:
    with make_client("127.0.0.1", proxy_headers=True, forwarded_allow_ips="127.0.0.1") as client:
        response = client.get("/probe")

    assert response.json() == {"client_ip": "127.0.0.1", "scheme": "http"}


@pytest.mark.parametrize("name", ["Forwarded", "CF-Connecting-IP", "X-Real-IP"])
def test_other_address_headers_do_not_select_the_client_even_from_a_trusted_peer(
    name: str,
) -> None:
    with make_client("127.0.0.1", proxy_headers=True, forwarded_allow_ips="127.0.0.1") as client:
        response = client.get("/probe", headers={name: "198.51.100.20"})

    assert response.json()["client_ip"] == "127.0.0.1"


def test_invalid_address_rewritten_by_a_trusted_proxy_is_still_rejected() -> None:
    with make_client("127.0.0.1", proxy_headers=True, forwarded_allow_ips="127.0.0.1") as client:
        with pytest.raises(ClientIPUnavailable, match=r"^Client address is unavailable\.$"):
            client.get("/probe", headers={"X-Forwarded-For": "invalid-address"})
