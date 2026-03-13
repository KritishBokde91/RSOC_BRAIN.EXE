from __future__ import annotations


class PaymentGateway:
    def __init__(self, api_key: str | None) -> None:
        if not api_key:
            raise ValueError("PAYMENT_API_KEY is required")
        self.api_key = api_key

    def healthcheck(self) -> str:
        return "connected"
