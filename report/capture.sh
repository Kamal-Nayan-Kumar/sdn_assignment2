#!/usr/bin/env bash
# Capture terminal screenshots for the LaTeX report.
#
# Each figure's command is run inside `script(1)`, which allocates a pty
# so the output keeps its ANSI colours and line buffering. The transcript
# is then rendered to a styled PNG in report/figs/ by render_term.py.
#
# Usage:
#   bash report/capture.sh            # capture everything
#   bash report/capture.sh tests      # capture only the named figures
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$HERE")
FIGS="$HERE/figs"
LOGS="$HERE/.logs"
RENDER="$HERE/render_term.py"
PY="${PY:-$ROOT/.venv/bin/python}"

mkdir -p "$FIGS" "$LOGS"

WANTED=("$@")

want() {  # want <figure-name>
  [ ${#WANTED[@]} -eq 0 ] && return 0
  local w
  for w in "${WANTED[@]}"; do [ "$w" = "$1" ] && return 0; done
  return 1
}

# The three e2e figures come from one run, so any of them implies the run.
want_e2e() { want e2e || want pingall || want dptable || want poxlog; }

# shot <figure-name> <title> <displayed-command> <script-body>
#
# <script-body> is shell source executed inside the pty; $CMD is available
# as the pretty command line shown in the screenshot's prompt.
shot() {
  local name=$1 title=$2 cmdline=$3 body=$4

  local runner="$LOGS/.runner.$name.sh"
  local log="$LOGS/$name.ansi"

  cat > "$runner" <<EOF
CMD='$cmdline'
printf '\033[1;36m\$\033[0m \033[1m%s\033[0m\n\n' "\$CMD"
$body
printf '\n'
exit
EOF

  echo "[capture] $name"
  script -qec "bash $runner" /dev/null > "$log" 2>/dev/null
  rm -f "$runner"

  "$PY" "$RENDER" "$log" "$FIGS/$name.png" --title "$title"
}

# ------------------------------------------------------------------ #
# 1. Offline test suite                                               #
# ------------------------------------------------------------------ #
if want tests; then
  shot tests "pytest -v" \
    ".venv/bin/python -m pytest tests/ -v" \
    "cd '$ROOT' && '$PY' -m pytest tests/ -v --color=yes"
fi

# ------------------------------------------------------------------ #
# 2. LLM intent -> policy (Part 2)                                    #
# ------------------------------------------------------------------ #
if want intent; then
  # Deliberately a live run: this is the assignment's exact administrator
  # request, and it shows the real LLM call plus the JSON policy it writes.
  # The JSON policy is the canonical file the POX controller loads.
  shot intent "intent_to_policy.py" \
    '.venv/bin/python intent_to_policy.py "Block h1 from sending traffic to h3." "Block h2 from sending traffic to h4." "Allow everything else." -f json' \
    "cd '$ROOT' && '$PY' intent_to_policy.py 'Block h1 from sending traffic to h3.' 'Block h2 from sending traffic to h4.' 'Allow everything else.' -f json -o '$ROOT/firewall_rules.rules'
printf '\n\033[1;36m\$\033[0m \033[1mcat firewall_rules.rules\033[0m\n\n'
cat '$ROOT/firewall_rules.rules'"
fi

# ------------------------------------------------------------------ #
# 3-5. Live end-to-end Mininet run (Part 1)                           #
# ------------------------------------------------------------------ #
if want_e2e; then
  echo "[capture] e2e: POX + oswitch + Mininet inside a user namespace"

  # run_e2e.sh owns the bring-up; --batch feeds it the scripted Mininet CLI
  # commands (via `mn --post`) and exits, so the whole run is
  # non-interactive. The pty from `script` is what makes mininet/ping emit
  # colour. NOTE: no `<<CLI` heredoc -- stdin is needed for the Mininet CLI.
  shot e2e "end-to-end: unshare -Urn bash run_e2e.sh --batch" \
    "unshare -Urn bash run_e2e.sh --batch" \
    "cd '$ROOT' && unshare -Urn bash run_e2e.sh --batch"

  # Slice the single transcript into per-topic figures.
  if [ -s "$LOGS/e2e.ansi" ]; then
    "$PY" "$HERE/split_e2e.py" "$LOGS/e2e.ansi" "$FIGS"
  else
    echo "[capture] WARNING: e2e transcript is empty"
  fi
fi

# ------------------------------------------------------------------ #
echo
echo "[capture] figures in $FIGS:"
ls -1 "$FIGS"/*.png 2>/dev/null || echo "  (none yet)"
