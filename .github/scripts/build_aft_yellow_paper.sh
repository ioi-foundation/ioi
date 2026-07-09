#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SPEC_DIR="${ROOT_DIR}/internal-docs/architecture/protocols/aft/specs"
OUTPUT_DIR="${ROOT_DIR}/internal-docs/formal/aft/generated/specs"

mkdir -p "${OUTPUT_DIR}"

pushd "${SPEC_DIR}" >/dev/null
pdflatex -interaction=nonstopmode -halt-on-error -output-directory="${OUTPUT_DIR}" yellow_paper.tex
pdflatex -interaction=nonstopmode -halt-on-error -output-directory="${OUTPUT_DIR}" yellow_paper.tex
popd >/dev/null
