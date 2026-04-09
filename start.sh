#!/bin/bash
# ZSE Startup — explicit PORT handling for Railway
set -e

PORT="${PORT:-8000}"
echo "============================================"
echo "  ZSE starting on port $PORT"
echo "  PID: $$"
echo "  Python: $(python --version)"
echo "============================================"

exec uvicorn app.main:app --host 0.0.0.0 --port "$PORT" --log-level info
