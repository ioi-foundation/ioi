#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SPEC_DIR="${ROOT_DIR}/docs/consensus/aft/specs"

pushd "${SPEC_DIR}" >/dev/null
pdflatex -interaction=nonstopmode -halt-on-error yellow_paper.tex
pdflatex -interaction=nonstopmode -halt-on-error yellow_paper.tex
popd >/dev/null
