"""Application entry point; domain modules will be added in focused slices."""

from typing import Literal

from fastapi import FastAPI
from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: Literal["ok"] = "ok"
    service: Literal["mazda6-assistant-api"] = "mazda6-assistant-api"


app = FastAPI(title="Mazda6 AI Assistant API", version="0.1.0")


@app.get("/api/v1/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Report process liveness; this does not check future external services."""
    return HealthResponse()
