#!/usr/bin/env bash
# End-to-end SDN Assignment 2 run: POX controller + Mininet + oswitch.py.
#
# Everything runs inside one user namespace (no sudo required on this box).
#
# Usage:
#   unshare -Urn bash run_e2e.sh            # interactive Mininet CLI
#   unshare -Urn bash run_e2e.sh --batch    # run the scripted CLI checks
#
# Evidence lands in logs/ and /tmp/opencode/.
set -u

cd "$(dirname "$0")"
ROOT=$PWD
export PYTHONPATH="$ROOT/mininet"

# Mininet expects an `mnexec` helper on PATH, and this repo ships an `ifconfig`
# shim that translates ifconfig -> ip (the system has iproute2 only).
export PATH="$ROOT/mininet:$ROOT/shim:$PATH"

# Build mnexec if absent (a stale timestamp makes `make` wrongly say it is
# up to date while the binary does not exist).
if [ ! -x "$ROOT/mininet/mnexec" ]; then
  echo "[e2e] building mnexec..."
  make -C "$ROOT/mininet" mnexec || exit 1
fi

mkdir -p "$ROOT/logs"

pkill -f pox.py 2>/dev/null
pkill -f oswitch.py 2>/dev/null
sleep 1

echo "[e2e] starting POX controller..."
# NOTE: the POX module is just `firewall`, not `pox.ext.firewall` --
# pox/boot.py adds pox/ext to sys.path itself.
nohup python pox/pox.py firewall > "$ROOT/logs/pox.log" 2>&1 &
sleep 6

if ! grep -q "POX 0.7.0.*is up" "$ROOT/logs/pox.log"; then
  echo "[e2e] controller failed to start:"; tail -20 "$ROOT/logs/pox.log"; exit 1
fi
echo "[e2e] controller up."

# Logging into the project directory (not /tmp) keeps evidence after the
# network namespace goes away.
echo "[e2e] policy:"
cat "$ROOT/firewall_rules.rules"

# This mininet (2.3-era) has no `--batch`; it runs the interactive CLI
# *before* the `--post` script.  stdin must therefore be at EOF (or a
# non-tty) for the interactive pass to finish and the scripted checks to
# run -- hence the `< /dev/null`.  report/mininet_cli.txt holds the checks.
if [ "${1:-}" = "--batch" ]; then
  echo "[e2e] starting network (scripted)..."
  mn --custom topo2.py --topo fourhost \
     --controller remote,ip=127.0.0.1,port=6633 \
     --post "$ROOT/report/mininet_cli.txt" < /dev/null
  echo "[e2e] logs: $ROOT/logs/pox.log  $ROOT/logs/oswitch.log"
else
  echo "[e2e] starting network..."
  mn --custom topo2.py --topo fourhost \
     --controller remote,ip=127.0.0.1,port=6633
fi
