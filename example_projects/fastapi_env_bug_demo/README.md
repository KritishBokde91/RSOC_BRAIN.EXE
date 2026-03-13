# FastAPI Env Bug Demo

This project is intentionally broken at startup to demonstrate runtime/config
findings in the audit flow.

Expected audit behavior:

- install: pass
- run: fail

Intentional bug:

- the payment gateway client is created during module import
- `PAYMENT_API_KEY` is required but not provided by default

Manual run:

```bash
python -m pip install -r requirements.txt
python main.py
```

Example env file:

```bash
PAYMENT_API_KEY=demo-secret
```
