"""Origin checks for cookie-authenticated state-changing endpoints."""

from typing import cast

from fastapi import HTTPException, Request, status

from app.config import Settings


async def require_trusted_origin(request: Request) -> None:
    """Reject requests without exactly one explicitly trusted browser origin."""
    settings = cast(Settings, request.app.state.settings)
    origins = request.headers.getlist("origin")

    if (
        len(origins) != 1
        or origins[0] in {"", "null"}
        or origins[0] not in settings.csrf_trusted_origins
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Request origin is not allowed.",
            headers={"Cache-Control": "no-store"},
        )
