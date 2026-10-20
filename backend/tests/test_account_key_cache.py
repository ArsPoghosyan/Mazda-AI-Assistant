"""Offline tests for account-key caching, rotation, and refresh control."""

import asyncio
from base64 import urlsafe_b64encode
from dataclasses import dataclass
from unittest.mock import AsyncMock

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from app.account_key_cache import AccountKeyCache
from app.account_key_fetch import AccountKeyFetchError
from app.account_keys import AccountKeyNotFound

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@dataclass
class FakeClock:
    now: float = 0.0

    def __call__(self) -> float:
        return self.now


def make_key_set(key_id: str) -> dict[str, object]:
    public_key = ec.generate_private_key(ec.SECP256R1()).public_key()
    numbers = public_key.public_numbers()

    return {
        "keys": [
            {
                "kid": key_id,
                "kty": "EC",
                "crv": "P-256",
                "alg": "ES256",
                "use": "sig",
                "key_ops": ["verify"],
                "x": urlsafe_b64encode(numbers.x.to_bytes(32, "big")).decode().rstrip("="),
                "y": urlsafe_b64encode(numbers.y.to_bytes(32, "big")).decode().rstrip("="),
            }
        ]
    }


@pytest.fixture
def key_set() -> dict[str, object]:
    return make_key_set("current-key")


async def test_reuses_keys_until_exact_expiry(
    key_set: dict[str, object],
) -> None:
    clock = FakeClock()
    fetcher = AsyncMock(return_value=key_set)
    cache = AccountKeyCache(fetcher, clock=clock)

    first = await cache.get_public_key("current-key")

    clock.now = 299.999
    cached = await cache.get_public_key("current-key")

    assert cached.public_numbers() == first.public_numbers()
    assert fetcher.await_count == 1

    clock.now = 300.0
    refreshed = await cache.get_public_key("current-key")

    assert refreshed.public_numbers() == first.public_numbers()
    assert fetcher.await_count == 2


async def test_unknown_ids_share_the_refresh_cooldown(
    key_set: dict[str, object],
) -> None:
    clock = FakeClock()
    fetcher = AsyncMock(return_value=key_set)
    cache = AccountKeyCache(fetcher, clock=clock)

    await cache.get_public_key("current-key")

    clock.now = 29.999

    for key_id in ("unknown-one", "unknown-two"):
        with pytest.raises(AccountKeyNotFound):
            await cache.get_public_key(key_id)

    assert fetcher.await_count == 1

    clock.now = 30.0

    with pytest.raises(AccountKeyNotFound):
        await cache.get_public_key("unknown-three")

    with pytest.raises(AccountKeyNotFound):
        await cache.get_public_key("unknown-four")

    assert fetcher.await_count == 2


async def test_rotation_replaces_the_previous_key_set(
    key_set: dict[str, object],
) -> None:
    clock = FakeClock()
    rotated = make_key_set("rotated-key")
    fetcher = AsyncMock(side_effect=[key_set, rotated])
    cache = AccountKeyCache(fetcher, clock=clock)

    previous = await cache.get_public_key("current-key")

    clock.now = 30.0
    current = await cache.get_public_key("rotated-key")

    assert current.public_numbers() != previous.public_numbers()

    with pytest.raises(AccountKeyNotFound):
        await cache.get_public_key("current-key")

    assert fetcher.await_count == 2


async def test_failed_initial_fetch_waits_before_retrying(
    key_set: dict[str, object],
) -> None:
    clock = FakeClock()
    fetcher = AsyncMock(side_effect=[AccountKeyFetchError("unavailable"), key_set])
    cache = AccountKeyCache(fetcher, clock=clock)

    with pytest.raises(AccountKeyFetchError):
        await cache.get_public_key("current-key")

    clock.now = 29.999

    with pytest.raises(AccountKeyFetchError):
        await cache.get_public_key("current-key")

    assert fetcher.await_count == 1

    clock.now = 30.0
    await cache.get_public_key("current-key")

    assert fetcher.await_count == 2


async def test_failed_refresh_preserves_only_unexpired_keys(
    key_set: dict[str, object],
) -> None:
    clock = FakeClock()
    fetcher = AsyncMock(
        side_effect=[
            key_set,
            AccountKeyFetchError("unavailable"),
            AccountKeyFetchError("unavailable"),
        ]
    )
    cache = AccountKeyCache(fetcher, clock=clock)

    original = await cache.get_public_key("current-key")

    clock.now = 30.0

    with pytest.raises(AccountKeyFetchError):
        await cache.get_public_key("unknown-key")

    clock.now = 299.999
    cached = await cache.get_public_key("current-key")

    assert cached.public_numbers() == original.public_numbers()
    assert fetcher.await_count == 2

    clock.now = 300.0

    with pytest.raises(AccountKeyFetchError):
        await cache.get_public_key("current-key")

    clock.now = 329.999

    with pytest.raises(AccountKeyFetchError):
        await cache.get_public_key("current-key")

    assert fetcher.await_count == 3


async def test_invalid_download_does_not_replace_valid_cached_keys(
    key_set: dict[str, object],
) -> None:
    clock = FakeClock()
    fetcher = AsyncMock(side_effect=[key_set, {"keys": [None]}])
    cache = AccountKeyCache(fetcher, clock=clock)

    original = await cache.get_public_key("current-key")

    clock.now = 30.0

    with pytest.raises(AccountKeyFetchError, match="Invalid"):
        await cache.get_public_key("unknown-key")

    cached = await cache.get_public_key("current-key")

    assert cached.public_numbers() == original.public_numbers()
    assert fetcher.await_count == 2


async def test_concurrent_requests_share_one_download(
    key_set: dict[str, object],
) -> None:
    started = asyncio.Event()
    release = asyncio.Event()

    async def download() -> dict[str, object]:
        started.set()
        await release.wait()
        return key_set

    fetcher = AsyncMock(side_effect=download)
    cache = AccountKeyCache(fetcher, clock=FakeClock())

    tasks = [asyncio.create_task(cache.get_public_key("current-key")) for _ in range(8)]

    try:
        await asyncio.wait_for(started.wait(), timeout=2)
        assert fetcher.await_count == 1
    finally:
        release.set()

    keys = await asyncio.wait_for(asyncio.gather(*tasks), timeout=2)

    assert len(keys) == 8
    assert all(key.public_numbers() == keys[0].public_numbers() for key in keys)
    assert fetcher.await_count == 1


async def test_cancelled_download_keeps_the_retry_cooldown(
    key_set: dict[str, object],
) -> None:
    clock = FakeClock()
    started = asyncio.Event()
    release = asyncio.Event()

    async def download() -> dict[str, object]:
        started.set()
        await release.wait()
        return key_set

    fetcher = AsyncMock(side_effect=download)
    cache = AccountKeyCache(fetcher, clock=clock)
    task = asyncio.create_task(cache.get_public_key("current-key"))

    await asyncio.wait_for(started.wait(), timeout=2)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, timeout=2)

    with pytest.raises(AccountKeyFetchError):
        await cache.get_public_key("current-key")

    assert fetcher.await_count == 1

    fetcher.side_effect = None
    fetcher.return_value = key_set
    clock.now = 30.0

    await cache.get_public_key("current-key")

    assert fetcher.await_count == 2


@pytest.mark.parametrize("key_id", ["", "x" * 129])
async def test_invalid_key_ids_do_not_trigger_downloads(
    key_set: dict[str, object],
    key_id: str,
) -> None:
    fetcher = AsyncMock(return_value=key_set)
    cache = AccountKeyCache(fetcher, clock=FakeClock())

    with pytest.raises(AccountKeyNotFound):
        await cache.get_public_key(key_id)

    fetcher.assert_not_awaited()
