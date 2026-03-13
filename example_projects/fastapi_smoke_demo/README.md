# FastAPI Smoke Demo

This is a small, self-contained example project for validating the
`AI Bug Detector` workflow.

Why this exists:

- install step is lightweight
- test step finishes quickly
- run step succeeds without requiring external APIs, databases, or secrets
- startup does not depend on `.env` values

## Files

- `main.py`: FastAPI app plus a short smoke-check entrypoint
- `requirements.txt`: minimal Python dependencies
- `test_app.py`: fast API and startup smoke tests

## Expected audit behavior

- install: should pass
- test: should pass
- run: `python main.py` should exit `0`

## Manual run

```bash
python -m pip install -r requirements.txt
pytest -q
python main.py
```

If you want to run the actual HTTP server manually:

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```
