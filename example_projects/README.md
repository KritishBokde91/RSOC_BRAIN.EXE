# Example Projects

These sample projects are meant for validating the `AI Bug Detector` flow.

## Clean project

- `fastapi_smoke_demo`
  - install should pass
  - tests should pass
  - run should pass

## Buggy projects

- `python_logic_bug_demo`
  - install should pass
  - tests should fail because of intentional logic bugs
  - run should still start and exit successfully

- `fastapi_env_bug_demo`
  - install should pass
  - run should fail because a required environment variable is missing during startup

Use these as quick smoke targets from the audit UI without needing external services.
