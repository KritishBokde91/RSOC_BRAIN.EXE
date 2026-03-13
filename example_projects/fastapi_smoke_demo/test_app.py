from fastapi.testclient import TestClient

from main import app, startup_check


client = TestClient(app)


def test_health_endpoint() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "fastapi-smoke-demo",
    }


def test_sum_endpoint() -> None:
    response = client.post("/sum", json={"left": 7, "right": 5})

    assert response.status_code == 200
    assert response.json() == {"result": 12}


def test_startup_check() -> None:
    summary = startup_check()

    assert summary["status"] == "ok"
    assert summary["environment"] == "development"
    assert summary["route_count"] >= 2
