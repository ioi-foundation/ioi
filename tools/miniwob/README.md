# MiniWoB Bridge

The `computer_use_suite` bridge keeps the Rust browser harness on the same MiniWoB page it is scoring.

Preferred setup:

```bash
git clone https://github.com/Farama-Foundation/miniwob-plusplus /tmp/miniwob-plusplus
export COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-plusplus
python3 tools/miniwob/bridge.py --host 127.0.0.1 --port 8765
```

One-command local suite run:

```bash
export COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-plusplus
tools/miniwob/run_suite.sh
```

Generic env-driven suite entrypoint:

```bash
export COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-plusplus
export COMPUTER_USE_SUITE_MODE=agent
export COMPUTER_USE_SUITE_TASK_SET=core
export COMPUTER_USE_SUITE_CASES=miniwob_click_option_core
tools/miniwob/run_suite.sh
```

Single-case diagnostic loop:

```bash
export COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-plusplus
tools/miniwob/run_case_diagnostics.sh miniwob_catalog_chase_circle
```

This wrapper runs one exact MiniWoB case, then renders
`diagnostic_summary.json` and `diagnostic_summary.md` inside that case's
artifact directory. The markdown report is also printed to stdout so you can
read the run as a play-by-play without opening the raw JSON files by hand.
The diagnostics include the full bounded bridge sync history, trigger labels,
reward transitions, and the agent tool timeline for the exact case.

Catalog baseline wrapper:

```bash
export COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-plusplus
export COMPUTER_USE_SUITE_MAX_CASES=20
tools/miniwob/run_catalog_baseline.sh
```

CI-oriented smoke wrapper:

```bash
export COMPUTER_USE_SUITE_MINIWOB_SOURCE_DIR=/tmp/miniwob-plusplus
tools/miniwob/run_ci_smoke.sh
```

Fallback setup:

```bash
python3 -m pip install -r tools/miniwob/requirements.txt
python3 tools/miniwob/bridge.py --host 127.0.0.1 --port 8765
```

Endpoints:

- `POST /session/create`
- `POST /session/{id}/reset`
- `GET /session/{id}/state`
- `GET /session/{id}/url`
- `POST /session/{id}/oracle_step`
- `POST /session/{id}/close`

The bridge materializes instrumented `file://` task pages in a temp directory and receives state syncs from the page itself. `oracle_step` is reserved for suite sanity checks; realistic modes still act through repo browser tools.

Useful env vars:

- `COMPUTER_USE_SUITE_TASK_SET=catalog` discovers every task HTML under the configured MiniWoB checkout.
- `COMPUTER_USE_SUITE_FAIL_ON_FAILURE=0` keeps baseline runs going so gap reports are still emitted when many tasks fail.
