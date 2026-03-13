from __future__ import annotations

import os

from fastapi import FastAPI
from pydantic import BaseModel, Field


app = FastAPI(
    title="FastAPI Smoke Demo",
    version="1.0.0",
    description="A small demo project for validating the AI Bug Detector flow.",
)


class SumRequest(BaseModel):
    left: int = Field(..., description="First integer")
    right: int = Field(..., description="Second integer")


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "fastapi-smoke-demo",
    }


@app.post("/sum")
def sum_numbers(payload: SumRequest) -> dict[str, int]:
    return {"result": payload.left + payload.right}


def startup_check() -> dict[str, int | str]:
    environment = os.getenv("APP_ENV", "development")
    return {
        "status": "ok",
        "environment": environment,
        "route_count": len(app.routes),
    }


if __name__ == "__main__":
    summary = startup_check()
    print(
        "startup-check:"
        f" status={summary['status']}"
        f" environment={summary['environment']}"
        f" route_count={summary['route_count']}"
    )
