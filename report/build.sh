#!/usr/bin/env bash
# Compile report/report.tex to PDF.
#
# Tries latexmk, then pdflatex+bibtex, then tectonic -- whichever is
# installed. Missing screenshots degrade to placeholders, so the build
# never fails just because a figure was not captured yet.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE"

if command -v latexmk >/dev/null 2>&1; then
  exec latexmk -pdf -interaction=nonstopmode -halt-on-error report.tex
fi

if command -v pdflatex >/dev/null 2>&1; then
  pdflatex -interaction=nonstopmode -halt-on-error report.tex >/dev/null
  pdflatex -interaction=nonstopmode -halt-on-error report.tex
  echo "[build] report/report.pdf"
  exit 0
fi

if command -v tectonic >/dev/null 2>&1; then
  exec tectonic -X compile report.tex --keep-logs
fi

cat <<'EOF'
[build] No LaTeX engine found.

Install one of:
  pacman -S texlive-latex-recommended texlive-latexextra texlive-pictures
  # or a single self-contained binary:
  #   https://github.com/tectonic-typesetting/tectonic/releases

Or compile elsewhere:
  pdflatex report.tex && pdflatex report.tex
EOF
exit 1
