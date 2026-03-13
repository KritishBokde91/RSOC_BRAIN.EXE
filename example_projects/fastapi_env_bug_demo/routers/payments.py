from __future__ import annotations

from fastapi import APIRouter

from config import PAYMENT_API_KEY
from services.payment_gateway import PaymentGateway


router = APIRouter(prefix="/payments", tags=["payments"])

# Intentional bug: client creation happens during import, so missing env
# configuration crashes app startup.
gateway = PaymentGateway(PAYMENT_API_KEY)


@router.get("/health")
def payment_health() -> dict[str, str]:
    return {"gateway": gateway.healthcheck()}
