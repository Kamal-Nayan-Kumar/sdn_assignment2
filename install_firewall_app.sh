#!/usr/bin/env bash
# Install our firewall application into the vendored POX tree.
#
# Why this script exists: pox/ is a nested git checkout of upstream POX, and
# upstream's own .gitignore contains `ext/*` -- so an app placed in
# pox/ext/ cannot be tracked by *this* repository at all.  That in turn means
# a `git clone` of this project arrives with no firewall application, which is
# the single most important file in the submission.
#
# So the authoritative copy lives in app/firewall.py (tracked here), and this
# script copies it to where POX expects to find it: pox/ext/firewall.py.
#
# It must be run before starting the controller.  run_e2e.sh and
# report/capture.sh both call it.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT="$HERE"

SRC="$ROOT/app/firewall.py"
DEST="$ROOT/pox/ext/firewall.py"

if [ ! -f "$SRC" ]; then
  echo "[install] FATAL: missing $SRC" >&2
  exit 1
fi

mkdir -p "$(dirname "$DEST")"

# -p keeps the destination's mode; -f overwrites.  A no-op if already current.
if [ -f "$DEST" ] && cmp -s "$SRC" "$DEST"; then
  echo "[install] pox/ext/firewall.py is already current"
else
  cp -f "$SRC" "$DEST"
  echo "[install] installed app/firewall.py -> pox/ext/firewall.py"
fi
