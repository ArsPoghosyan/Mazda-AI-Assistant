"""Application entry point and operational health endpoints."""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Literal, cast

from fastapi import FastAPI, Response
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncEngine

from app.config import Settings
from app.database import create_database_engine, database_is_ready


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
        engine = create_database_engine(configuration)

        application.state.settings = configuration
        application.state.database_engine = engine

        try:
            yield
        finally:
            if engine is not None:
                await engine.dispose()
            application.state.database_engine = None

    application = FastAPI(
        title="Mazda6 AI Assistant API",
        version="0.1.0",
        lifespan=lifespan,
    )

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
