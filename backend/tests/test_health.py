from fastapi.testclient import TestClient

from app.main import app


def test_health_contract() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/health")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert response.json() == {"status": "ok", "service": "mazda6-assistant-api"}
