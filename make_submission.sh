#!/usr/bin/env bash
# Build the assignment submission bundle.
#
# Layout requested for submission:
#
#   sdn_assignment2_submission.zip
#   ├── report.pdf            the report (single PDF: all explanation +
#   │                         screenshots) -- the headline artefact
#   └── code/                 everything else: source, tests, scripts,
#                             the policy file, figures and LaTeX source
#
# The vendored pox/ and mininet/ trees are third-party (cloned separately)
# and are excluded, as are .venv/, .git/ and runtime logs.
#
# Usage: bash make_submission.sh [output.zip]
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT="$HERE"
OUT=${1:-"$ROOT/sdn_assignment2_submission.zip"}
STAGE=$(mktemp -d /tmp/opencode/submission.XXXXXX)

echo "[submit] staging in $STAGE"

# The app must be in place before anything reads it.
bash "$ROOT/install_firewall_app.sh"

# ------------------------------------------------------------------ #
# 1. The report, at the top level                                    #
# ------------------------------------------------------------------ #
if [ -f "$ROOT/report/report.pdf" ]; then
  cp "$ROOT/report/report.pdf" "$STAGE/report.pdf"
  echo "[submit] report.pdf"
else
  echo "[submit] FATAL: report/report.pdf missing -- build it first:" >&2
  echo "        bash report/build.sh" >&2
  rm -rf "$STAGE"
  exit 1
fi

# ------------------------------------------------------------------ #
# 2. Everything else, under code/                                    #
# ------------------------------------------------------------------ #
CODE="$STAGE/code"
mkdir -p "$CODE"

COPY=(
  # ---- this assignment's source ------------------------------------
  app/firewall.py
  pox/ext/firewall.py
  oswitch.py
  topo2.py
  intent_to_policy.py
  firewall_rules.rules

  # ---- scripts ------------------------------------------------------
  run_e2e.sh
  install_firewall_app.sh
  run_all.sh
  shim/ifconfig

  # ---- tests --------------------------------------------------------
  tests/test_firewall.py
  tests/test_oswitch_wire.py
  tests/test_intent_to_policy.py

  # ---- report source and evidence (the PDF itself is at the top) ----
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

  # ---- docs ---------------------------------------------------------
  README.md
  COMMAND.md
  mise.toml
  .gitignore

  # ---- the assignment statement ------------------------------------
  "SDN_Assignment2 2026.pdf"
)

for f in "${COPY[@]}"; do
  if [ -e "$ROOT/$f" ]; then
    mkdir -p "$CODE/$(dirname "$f")"
    cp "$ROOT/$f" "$CODE/$f"
  else
    echo "[submit] WARNING: missing $f" >&2
  fi
done

# figures -> code/report/figs/
mkdir -p "$CODE/report/figs"
for png in "$ROOT"/report/figs/*.png; do
  [ -e "$png" ] && cp "$png" "$CODE/report/figs/"
done

# ------------------------------------------------------------------ #
# 3. A root-level note, since run_all.sh lives in code/              #
# ------------------------------------------------------------------ #
cat > "$STAGE/HOW_TO_RUN.md" <<'EOF'
# SDN Assignment 2

**`report.pdf`** — the report: architecture, implementation details,
environment setup, known limitations, results, and all screenshots.
Read this first.

**`code/`** — everything needed to reproduce the results. See
`code/COMMAND.md` for the full command list and `code/README.md` for an
overview.

Quick start, from inside `code/`:

```bash
python3 -m pytest tests/ -q        # 51 offline tests, ~1s, no network
unshare -Urn bash run_e2e.sh --batch   # full end-to-end: 33% dropped
```

`run_all.sh` runs both in sequence and prints what it did.
EOF

# Make the scripts runnable in the bundle.
chmod +x "$CODE"/*.sh "$CODE"/tests/*.sh 2>/dev/null || true

# ------------------------------------------------------------------ #
# 4. Zip it                                                          #
# ------------------------------------------------------------------ #
rm -f "$OUT"
(cd "$STAGE" && zip -qr "$OUT" .)

echo
echo "[submit] wrote $OUT ($(du -h "$OUT" | cut -f1))"
echo
echo "[submit] top level:"
(cd "$STAGE" && unzip -l "$OUT" | awk 'NR>3 && $4 !~ /\// {printf "  %s  %s\n", $1, $4}' | grep -v "^  *$" | grep -v "^-" )
echo
echo "[submit] under code/:"
(cd "$STAGE" && unzip -l "$OUT" | awk -v p="code/" 'index($4,p)==1 {printf "  %s  %s\n", $1, $4}')

rm -rf "$STAGE"
