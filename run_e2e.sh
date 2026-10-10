#!/usr/bin/env bash
# End-to-end SDN Assignment 2 run: POX controller + Mininet + oswitch.py.
#
# Everything runs inside one user namespace (no sudo required on this box).
# Usage:  bash run_e2e.sh
set -u

cd "$(dirname "$0")"
ROOT=$PWD
export PYTHONPATH="$ROOT/mininet"

# Mininet expects an `mnexec` helper on PATH.
export PATH="$ROOT/mininet:$ROOT/shim:$PATH"

# Build mnexec if absent (a stale timestamp makes `make` wrongly say it is
# up to date).
if [ ! -x "$ROOT/mininet/mnexec" ]; then
  echo "[e2e] building mnexec..."
  make -C "$ROOT/mininet" mnexec || exit 1
fi

pkill -f pox.py 2>/dev/null
pkill -f oswitch.py 2>/dev/null
sleep 1

echo "[e2e] starting POX controller..."
# NOTE: the POX module is just `firewall`, not `pox.ext.firewall` --
# pox/boot.py adds pox/ext to sys.path itself.
nohup python pox/pox.py firewall > /tmp/pox.log 2>&1 &
sleep 6

if ! grep -q "POX 0.7.0.*is up" /tmp/pox.log; then
  echo "[e2e] controller failed to start:"; tail -20 /tmp/pox.log; exit 1
fi
echo "[e2e] controller up."

echo "[e2e] starting network..."
python run_demo.py < /dev/null

echo "[e2e] logs: /tmp/pox.log  /tmp/oswitch.log"