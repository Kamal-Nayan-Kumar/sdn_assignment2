#!/usr/bin/env bash
# Model selection benchmark for Part 2 of the report.
#
# Only models currently pulled into Ollama are timed, so after the losers
# were deleted this reports the chosen model alone.  To re-run the full
# comparison, pull the losers first:
#
#   ollama pull phi3 gemma2:2b qwen2.5:1.5b llama3.2:1b
#   bash report/bench_models.sh
set -eu
cd "$(dirname "$0")/.."
.venv/bin/python report/bench_models.py
