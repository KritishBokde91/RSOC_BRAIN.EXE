# Python Logic Bug Demo

This project is intentionally buggy so the audit flow can surface failing tests.

Expected audit behavior:

- install: pass
- test: fail
- run: pass

Intentional bugs:

- `add_numbers()` subtracts instead of adding
- `average_numbers()` divides by `len(numbers) + 1`

Manual run:

```bash
python -m pip install -r requirements.txt
pytest -q
python main.py
```
