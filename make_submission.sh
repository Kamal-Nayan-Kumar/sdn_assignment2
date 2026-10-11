#!/usr/bin/env bash
# Build the assignment submission bundle.
#
# Produces a single archive containing:
#   report.pdf            the report (single PDF, all explanations + figures)
#   report/report.tex     its LaTeX source
#   report/figs/*.png     every screenshot
#   app/, pox/ext/...     the firewall application
#   oswitch.py, topo2.py, intent_to_policy.py, run_e2e.sh, ...
#   tests/                the test suite
#   the source assignment PDF, for reference
#
# Deliberately excluded: the vendored pox/ and mininet/ checkouts (they are
# third-party and enormous), .venv/, .git/, runtime logs, and build noise.
#
# Usage: bash make_submission.sh [output.zip]
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT="$HERE"
OUT=${1:-"$ROOT/sdn_assignment2_submission.zip"}
STAGE=$(mktemp -d /tmp/opencode/submission.XXXXXX)

echo "[submit] staging in $STAGE"

# --- make sure the app is installed where POX expects it ----------------
bash "$ROOT/install_firewall_app.sh"

# ------------------------------------------------------------------ #
# Files that make up the deliverable                                #
# ------------------------------------------------------------------ #
FILES=(
  # --- report (the single PDF is the headline artefact) -------------
  report/report.pdf
  report/report.tex
  report/FIGURES.md
  report/mininet_cli.txt
  report/bench_models.py
  report/bench_models.sh
  report/build.sh
  report/capture.sh
  report/make.sh
  report/render_term.py
  report/split_e2e.py
  report/logo.jpeg
  report/model_benchmark.json

  # --- source code ---------------------------------------------------
  app/firewall.py
  pox/ext/firewall.py
  oswitch.py
  topo2.py
  intent_to_policy.py
  run_e2e.sh
  install_firewall_app.sh
  run_demo.py
  shim/ifconfig

  # --- tests ---------------------------------------------------------
  tests/test_firewall.py
  tests/test_oswitch_wire.py
  tests/test_intent_to_policy.py

  # --- policy and config ---------------------------------------------
  firewall_rules.rules
  mise.toml
  .gitignore

  # --- the assignment statement itself -------------------------------
  "SDN_Assignment2 2026.pdf"
)

for f in "${FILES[@]}"; do
  if [ -e "$ROOT/$f" ]; then
    mkdir -p "$STAGE/$(dirname "$f")"
    cp "$ROOT/$f" "$STAGE/$f"
  else
    # run_demo.py was dropped in an earlier commit; that is fine.
    [ "$f" = "run_demo.py" ] && continue
    echo "[submit] WARNING: missing $f" >&2
  fi
done

# figures
mkdir -p "$STAGE/report/figs"
for png in "$ROOT"/report/figs/*.png; do
  [ -e "$png" ] && cp "$png" "$STAGE/report/figs/"
done

# ------------------------------------------------------------------ #
# README: how to run it                                              #
# ------------------------------------------------------------------ #
cat > "$STAGE/README.md" <<'EOF'
# SDN Assignment 2 — Layer-2 Firewall & Intent-Based Networking

**Everything you need is in `report/report.pdf`** — the architecture,
implementation details, environment setup, known limitations, results, and
all screenshots.

## What is here

| Path | What it is |
|---|---|
| `report/report.pdf` | **The report. Start here.** |
| `report/report.tex`, `report/figs/` | LaTeX source and every screenshot |
| `app/firewall.py` | **The POX firewall application** (the main deliverable) |
| `pox/ext/firewall.py` | A copy, already where POX expects it |
| `oswitch.py` | Pure-Python OpenFlow 1.0 switch |
| `topo2.py` | Four-host Mininet topology |
| `intent_to_policy.py` | Natural-language → policy (qwen2.5:0.5b via Ollama) |
| `firewall_rules.rules` | The generated policy (h1→h3, h2→h4 DROP) |
| `tests/` | 51 offline tests |
| `SDN_Assignment2 2026.pdf` | The assignment statement |

## Running it

`pox/` and `mininet/` are third-party checkouts and are **not** included.
The code needs them on disk, but no network is required to read this.

```bash
# 1. Offline tests — no network, no LLM, ~1s
python3 -m pytest tests/ -q          # expect: 51 passed

# 2. Full end-to-end bring-up (POX + oswitch + Mininet)
bash run_e2e.sh --batch               # scripted: pingall + per-pair pings
bash run_e2e.sh                       # or interactive (drops into the CLI)

# 3. Part 2: natural-language intent → policy file
#    needs `ollama serve` and `ollama pull qwen2.5:0.5b`
python3 intent_to_policy.py \
    "Block h1 from sending traffic to h3." \
    "Block h2 from sending traffic to h4." \
    "Allow everything else." -f json

# 4. Rebuild the report
bash report/build.sh                  # tectonic or pdflatex
bash report/capture.sh                # regenerate every screenshot
```

All network commands must run inside a user namespace, because the target
machine has no `sudo`:

```bash
unshare -Urn bash run_e2e.sh --batch
```

## Expected result

`pingall` reports **33% dropped (8/12)**: the two prohibited pairs
(`h1→h3`, `h2→h4`) and their reverse directions. The reverse directions fail
as a consequence of ARP — the report explains why, and why that is the
correct reading of the assignment rather than a bug.
EOF

cat > "$STAGE/run_all.sh" <<'EOF'
#!/usr/bin/env bash
# Run every check in the submission, in order.
#   usage: bash run_all.sh [--no-e2e]
set -eu
cd "$(dirname "$0")"

PY=python3
[ -x .venv/bin/python ] && PY=.venv/bin/python

# The vendored POX and Mininet checkouts are third-party and are not shipped
# in this bundle.  Everything that needs them (the offline tests import POX to
# verify the OpenFlow wire format) will report a clear message here instead of
# an import traceback.
if [ ! -f pox/pox.py ]; then
  cat <<MSG
==========================================
 Missing third-party dependencies
==========================================
This bundle contains ONLY this assignment's code: the app, switch, topology,
LLM policy generator and tests.  To actually RUN the tests or the network you
also need the two checkouts this project builds on:

  git clone https://github.com/noxrepo/pox.git pox
  git clone https://github.com/mininet/mininet.git mininet
  make -C mininet

Then, from this directory:

  bash install_firewall_app.sh     # put app/firewall.py where POX wants it
  python3 -m pytest tests/ -q      # 51 tests
  unshare -Urn bash run_e2e.sh --batch

Nothing needs the network to READ the report: report/report.pdf has the
architecture, implementation, environment, limitations and results.
MSG
  exit 2
fi

echo "=========================================="
echo "1/4  Offline test suite"
echo "=========================================="
$PY -m pytest tests/ -q

echo
echo "=========================================="
echo "2/4  Policy file and the rules POX loads"
echo "=========================================="
cat firewall_rules.rules

if [ "${1:-}" != "--no-e2e" ]; then
  echo
  echo "=========================================="
  echo "3/4  End-to-end: POX + oswitch + Mininet"
  echo "=========================================="
  # Needs unshare for the user namespace; may need ./install_firewall_app.sh
  # first if pox/ is a fresh checkout.
  if unshare -Urn true 2>/dev/null; then
    unshare -Urn bash run_e2e.sh --batch
  else
    echo "  (skipped: unshare unavailable on this host)"
    bash run_e2e.sh --batch
  fi
fi

echo
echo "=========================================="
echo "4/4  Done. Report: report/report.pdf"
echo "=========================================="
EOF
chmod +x "$STAGE/run_all.sh"

# ------------------------------------------------------------------ #
# Zip it                                                             #
# ------------------------------------------------------------------ #
rm -f "$OUT"
(cd "$STAGE" && zip -qr "$OUT" .)
echo
echo "[submit] wrote $OUT"
ls -lh "$OUT"
echo
echo "[submit] contents:"
(cd "$STAGE" && unzip -l "$OUT" | tail -n +4 | head -n -2 | awk '{
  print $4"  "$1}')
rm -rf "$STAGE"
