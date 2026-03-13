from __future__ import annotations

from fastapi import FastAPI

from routers.payments import router as payments_router


app = FastAPI(title="FastAPI Env Bug Demo", version="1.0.0")
app.include_router(payments_router)


@app.get("/")
def root() -> dict[str, str]:
    return {"status": "ok"}


if __name__ == "__main__":
    print("startup-check: importing application")
