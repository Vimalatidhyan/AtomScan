---
name: prod-readiness-audit
description: Run the strict production readiness audit for Technieum. Use when validating the app before a release.
disable-model-invocation: true
allowed-tools: Bash(python *)
context: fork
agent: Explore
argument-hint: [--host 127.0.0.1 --port 8000]
---

## Task
Execute the full 8-phase audit and produce a PASS/FAIL report.

## Steps
1. Run the Python test runner from the repo root:
   - Command: `python tests/prod_readiness_test.py --host $0 --port $1 --base .`
   - Default: `--host 127.0.0.1 --port 8000`
2. Capture stdout and include the final scoring table plus failures.
3. If FAIL, list concrete fixes with file references to implement.

## Notes
- This is manual-invocation only. Use `/prod-readiness-audit 127.0.0.1 8000`.
- If the server is not running, start it in another terminal first.
