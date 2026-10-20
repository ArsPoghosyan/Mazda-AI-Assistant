"""Bounded, process-local caching of account-signing key sets."""

import asyncio
from collections.abc import Awaitable, Callable
from time import monotonic

from cryptography.hazmat.primitives.asymmetric import ec

from app.account_key_fetch import AccountKeyFetchError
from app.account_keys import (
    AccountKeyNotFound,
    InvalidAccountKeySet,
    select_account_public_key,
)

_CACHE_TTL_SECONDS = 300.0
_REFRESH_COOLDOWN_SECONDS = 30.0
_MAX_KEY_ID_CHARACTERS = 128


class AccountKeyCache:
    """Keep one downloaded key set and coordinate refresh attempts."""

    def __init__(
        self,
        fetch_keys: Callable[[], Awaitable[dict[str, object]]],
        *,
        clock: Callable[[], float] = monotonic,
    ) -> None:
        self._fetch_keys = fetch_keys
        self._clock = clock
        self._lock = asyncio.Lock()

        self._key_set: dict[str, object] | None = None
        self._expires_at = float("-inf")
        self._next_refresh_at = float("-inf")
        self._refresh_failed = False

    async def get_public_key(
        self,
        key_id: str,
    ) -> ec.EllipticCurvePublicKey:
        """Find a key, refreshing only when the cooldown permits."""

        if not key_id or len(key_id) > _MAX_KEY_ID_CHARACTERS:
            raise AccountKeyNotFound("Invalid account signing key identifier.")

        async with self._lock:
            now = self._clock()

            if self._key_set is not None and now < self._expires_at:
                try:
                    return self._select_key(self._key_set, key_id)
                except AccountKeyNotFound:
                    pass

            if now < self._next_refresh_at:
                if self._refresh_failed or self._key_set is None or now >= self._expires_at:
                    raise AccountKeyFetchError("Account signing keys are unavailable.")

                raise AccountKeyNotFound("Account signing key not found.")

            # Set the cooldown before awaiting the network request.
            # Failed or cancelled requests must not enable a retry storm.
            self._next_refresh_at = now + _REFRESH_COOLDOWN_SECONDS
            self._refresh_failed = True

            downloaded = await self._fetch_keys()

            try:
                public_key = self._select_key(downloaded, key_id)
            except AccountKeyNotFound:
                public_key = None

            # Replace the previous response rather than accumulating
            # entries for attacker-supplied key identifiers.
            refreshed_at = self._clock()
            self._key_set = downloaded
            self._expires_at = refreshed_at + _CACHE_TTL_SECONDS
            self._next_refresh_at = refreshed_at + _REFRESH_COOLDOWN_SECONDS
            self._refresh_failed = False

            if public_key is None:
                raise AccountKeyNotFound("Account signing key not found.")

            return public_key

    @staticmethod
    def _select_key(
        key_set: dict[str, object],
        key_id: str,
    ) -> ec.EllipticCurvePublicKey:
        try:
            return select_account_public_key(key_set, key_id=key_id)
        except InvalidAccountKeySet:
            raise AccountKeyFetchError("Invalid account signing key response.") from None
