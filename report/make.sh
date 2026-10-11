#!/usr/bin/env bash
# One-shot: capture every screenshot the report needs, then tell you
# whether a LaTeX engine is available to build the PDF.
#
#   bash report/make.sh
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$HERE")

echo "=============================================="
echo " 1/2  Capturing screenshots"
echo "=============================================="
bash "$HERE/capture.sh"

echo
echo "=============================================="
echo " 2/2  Building the PDF"
echo "=============================================="
bash "$HERE/build.sh" || echo
echo
echo "Compile manually with:  pdflatex report.tex && pdflatex report.tex"
