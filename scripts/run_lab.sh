#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python3 -m venv .venv
.venv/bin/pip install -r backend/requirements.lock
.venv/bin/python scripts/init_lab.py
PYTHONPATH=backend .venv/bin/uvicorn sentinel.app:app --host 127.0.0.1 --port 8000
