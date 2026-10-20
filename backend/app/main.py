"""Application entry point and operational health endpoints."""

from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager
from typing import Literal, cast

import httpx2
from fastapi import FastAPI, Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncEngine

from app.account_key_cache import AccountKeyCache
from app.account_key_fetch import fetch_account_key_set
from app.account_routes import router as account_router
from app.config import Settings
from app.database import create_database_engine, database_is_ready
from app.guest_routes import router as guest_router


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    service: Literal["mazda6-assistant-api"] = "mazda6-assistant-api"


class ReadinessResponse(BaseModel):
    status: Literal["ok", "unavailable"]
    service: Literal["mazda6-assistant-api"] = "mazda6-assistant-api"


def create_app(settings: Settings | None = None) -> FastAPI:
    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        configuration = settings if settings is not None else Settings()

        application.state.settings = configuration
        application.state.database_engine = None
        application.state.account_key_cache = None

        try:
            async with AsyncExitStack() as resources:
                engine = create_database_engine(configuration)

                if engine is not None:
                    resources.push_async_callback(engine.dispose)

                application.state.database_engine = engine

                if configuration.supabase_auth_issuer is not None:
                    client = await resources.enter_async_context(
                        httpx2.AsyncClient(
                            timeout=5.0,
                            follow_redirects=False,
                            trust_env=False,
                            limits=httpx2.Limits(
                                max_connections=1,
                                max_keepalive_connections=1,
                            ),
                        )
                    )

                    async def download_account_keys() -> dict[str, object]:
                        return await fetch_account_key_set(
                            configuration,
                            client=client,
                        )

                    application.state.account_key_cache = AccountKeyCache(download_account_keys)

                yield
        finally:
            application.state.account_key_cache = None
            application.state.database_engine = None

    application = FastAPI(
        title="Mazda6 AI Assistant API",
        version="0.1.0",
        lifespan=lifespan,
    )

    application.include_router(guest_router)
    application.include_router(account_router)

    @application.get("/api/v1/health", response_model=HealthResponse)
    async def health() -> HealthResponse:
        """Report process liveness independently of database availability."""
        return HealthResponse()

    @application.get(
        "/api/v1/ready",
        response_model=ReadinessResponse,
        responses={503: {"model": ReadinessResponse}},
    )
    async def readiness(response: Response) -> ReadinessResponse:
        """Report whether the database can currently serve queries."""
        configuration = cast(Settings, application.state.settings)
        engine = cast(
            AsyncEngine | None,
            application.state.database_engine,
        )

        ready = await database_is_ready(
            engine,
            configuration.db_readiness_timeout_seconds,
        )

        response.headers["Cache-Control"] = "no-store"
        if not ready:
            response.status_code = 503

        return ReadinessResponse(
            status="ok" if ready else "unavailable",
        )

    return application


app = create_app()
