#!/usr/bin/env bash
# Run every check in this assignment, in order.
#
#   usage: bash run_all.sh [--no-e2e]
#
# What it does, and why the order matters:
#   1. tests      offline, no network, no LLM. Must pass first, otherwise a
#                 later failure is ambiguous.
#   2. policy     shows the rules POX will load.
#   3. end-to-end the real network. Slow (~90s) and needs a user namespace.
#   4. summary
set -eu
cd "$(dirname "$0")"

PY=python3
[ -x .venv/bin/python ] && PY=.venv/bin/python

hr() { printf '=%.0s' {1..50}; echo; }

hr; echo " 1/4  Offline test suite  (~1s, no network)"; hr
$PY -m pytest tests/ -q
echo

hr; echo " 2/4  Policy file POX will load"; hr
cat firewall_rules.rules
echo

if [ "${1:-}" != "--no-e2e" ]; then
  if [ ! -f pox/pox.py ]; then
    echo "  Skipped: pox/ is not present (it is a third-party checkout)."
    echo "  Clone it and run install_firewall_app.sh first -- see README.md."
  else
    hr; echo " 3/4  End-to-end: POX + oswitch + Mininet  (~90s)"; hr
    if unshare -Urn true 2>/dev/null; then
      unshare -Urn bash run_e2e.sh --batch
    else
      echo "  (unshare unavailable here, running without a user namespace)"
      bash run_e2e.sh --batch
    fi
  fi
else
  hr; echo " 3/4  End-to-end  (skipped: --no-e2e)"; hr
fi

hr; echo " 4/4  Report: report/report.pdf   Commands: COMMAND.md"; hr
