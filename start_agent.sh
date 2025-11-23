#!/usr/bin/env bash
# Startup script for the Detection Agent FastAPI backend.
#
# Environment overrides honored by the backend:
#   AGENT_RESULTS_DIR / STATIC_RESULTS_DIR - Directory where payload execution JSON artifacts and logs
#                       are stored (defaults to ./static_results). STATIC_RESULTS_DIR is kept for legacy
#                       compatibility and is treated the same as AGENT_RESULTS_DIR.
#   LOG_PATH_<SOURCE> - Optional overrides for log ingestion paths (e.g., LOG_PATH_SYSLOG, LOG_PATH_AUDIT).
#                       These allow operators to point the agent at custom log locations.

set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
VENV_DIR="$SCRIPT_DIR/venv"

cd "$SCRIPT_DIR"

if [[ ! -d "$VENV_DIR" ]]; then
    echo "Creating virtual environment at $VENV_DIR ..."
    python3 -m venv "$VENV_DIR"
fi

# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"

echo "Installing/upgrading dependencies from requirements.txt ..."
pip install --upgrade pip
pip install --upgrade -r "$SCRIPT_DIR/requirements.txt"

if [[ -n "${PYTHONPATH:-}" ]]; then
    export PYTHONPATH="$SCRIPT_DIR:$PYTHONPATH"
else
    export PYTHONPATH="$SCRIPT_DIR"
fi

DEFAULT_RESULTS_DIR="$SCRIPT_DIR/static_results"
if [[ -n "${AGENT_RESULTS_DIR:-}" ]]; then
    ACTIVE_RESULTS_DIR="$AGENT_RESULTS_DIR"
elif [[ -n "${STATIC_RESULTS_DIR:-}" ]]; then
    ACTIVE_RESULTS_DIR="$STATIC_RESULTS_DIR"
else
    ACTIVE_RESULTS_DIR="$DEFAULT_RESULTS_DIR"
fi

echo ""
echo "Detection Agent FastAPI backend starting via uvicorn ..."
echo "API base URL        : http://localhost:8000"
echo "Interactive docs    : http://localhost:8000/docs"
echo "OpenAPI schema      : http://localhost:8000/openapi.json"
echo "Results directory   : $ACTIVE_RESULTS_DIR"
echo "(Override by exporting AGENT_RESULTS_DIR or STATIC_RESULTS_DIR before running this script.)"
echo ""
echo "Press Ctrl+C to stop the service."
echo ""

exec uvicorn agent_service.detection_agent_service:app --host 0.0.0.0 --port 8000

