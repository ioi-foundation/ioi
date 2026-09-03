#!/usr/bin/env bash
# AFT claim-discipline gate (AFT-CB program, leg P0.2).
#
# The AFT prose corpus must never print a rounded percentage as a Byzantine
# tolerance figure. With n = 16-64 validators the true all-but-one maximum is
# 93.75%-98.4375%, so a "99%" tolerance claim is never exact; the required
# form is "all-but-one (n-1 of n) Byzantine safety", conditional on the AFT
# model delta (the assumed common publication boundary).
#
# This gate scans internal-docs/architecture/protocols/aft/specs/ AND
# internal-docs/architecture/protocols/aft/formal/ (the formal-tree READMEs
# were outside the original fence and shipped six stale claims, found at
# AFT-CB P2.4) for any "99%" spelling (tex: 99\%, 99 \%, $99\%$; md: bare
# 99%) and fails on every hit that is not one of three narrow,
# content-matched allowances:
#   (a) a latency percentile token (p99) -- a measurement column, not a claim;
#   (b) a line describing PRIOR work that carries the explicit prior-art
#       marker "(their figure, not an AFT claim)" next to a named prior system
#       (Geeq's Proof of Honesty). The allowance matches line content, never a
#       whole file;
#   (c) an explicit retirement/requalification sentence -- the line names the
#       figure as retired ("retired ... 99"), cites the requalifying leg
#       ("requalified per AFT-CB"), or marks the bound historical ("is no
#       longer the normative"). Mentioning the dead figure while burying it
#       is allowed; asserting it is not.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SPECS_DIR="${ROOT_DIR}/internal-docs/architecture/protocols/aft/specs"
FORMAL_DIR="${ROOT_DIR}/internal-docs/architecture/protocols/aft/formal"

# 99 followed (after optional whitespace and optional TeX escape backslash)
# by a percent sign; also the plain TeX spelling 99\%.
PATTERN='99[[:space:]]*\\?%'

# (b) explicit prior-art marker: the Geeq prior-work sentence, matched by
# content (named prior system + "prior work" + "(their figure)").
PRIOR_ART_ALLOW="Geeq's Proof of Honesty.*prior work.*\(their figure, not an .{0,2}AFT.{0,2} claim\)"

# (c) retirement/requalification allowance, content-matched on the line.
RETIRED_ALLOW="retired.{0,20}99|requalified per AFT-CB|is no longer the normative"

if [ ! -d "${SPECS_DIR}" ]; then
  echo "check_aft_claim_discipline: specs dir not found: ${SPECS_DIR}" >&2
  exit 1
fi

violations=0
while IFS= read -r hit; do
  file="${hit%%:*}"
  rest="${hit#*:}"
  line_no="${rest%%:*}"
  line="${rest#*:}"

  # (a) latency percentile allowance: remove p99 tokens, then re-test. A line
  # that still matches after stripping p99 carries a real 99% spelling.
  stripped="$(printf '%s' "${line}" | sed -E 's/([^[:alnum:]]|^)p99([^[:alnum:]]|$)/\1\2/g')"
  if ! printf '%s' "${stripped}" | grep -qE "${PATTERN}"; then
    continue
  fi

  # (b) prior-art allowance, content-matched on the same line.
  if printf '%s' "${line}" | grep -qE "${PRIOR_ART_ALLOW}"; then
    continue
  fi

  # (c) retirement/requalification allowance, content-matched on the line.
  if printf '%s' "${line}" | grep -qE "${RETIRED_ALLOW}"; then
    continue
  fi

  echo "CLAIM-DISCIPLINE VIOLATION: ${file}:${line_no}:${line}"
  violations=$((violations + 1))
done < <(grep -rnE --include='*.tex' --include='*.md' "${PATTERN}" "${SPECS_DIR}" "${FORMAL_DIR}" || true)

if [ "${violations}" -ne 0 ]; then
  echo "FAIL: ${violations} unqualified 99% tolerance spelling(s) in the AFT specs/formal corpus." >&2
  echo "Required form: all-but-one (n-1 of n) Byzantine safety, conditional on the AFT model delta." >&2
  exit 1
fi

# AFT-CB P4.4 flagship-gating: neither flagship rung may appear in the
# corpus as a BARE assertion. The distinctive rung phrase "frontier-
# complete" may appear ONLY on a line that also carries a blocked/gated
# marker (BLOCKED, "does not print", "gated on", "unreachable", "cannot
# print", "REMAINING EDITORIAL", or the adjudication's quoting context).
# Both flagship rungs remain blocked (T8's supply bound is L-OPEN; responsive
# T5d is refuted by L-S; scheduled R12 still depends on RES-R11); a bare
# assertion of frontier-
# completeness is therefore a false claim and fails the gate. This gate
# is mutation-tested (AFT-CB standing rule 3): a bare "frontier-complete
# consensus architecture" line must turn it RED.
FLAGSHIP_PATTERN='frontier-complete'
FLAGSHIP_ALLOW='BLOCKED|does not print|cannot print|gated on|unreachable|REMAINING EDITORIAL|only where.*marked|no flagship rung|flagship rung is absent|flagship strings|frontier-completeness flagship|the .{0,3}frontier-complete.{0,3} strings'
flagship_violations=0
while IFS= read -r hit; do
  file="${hit%%:*}"
  rest="${hit#*:}"
  line_no="${rest%%:*}"
  line="${rest#*:}"
  if printf '%s' "${line}" | grep -qE "${FLAGSHIP_ALLOW}"; then
    continue
  fi
  echo "FLAGSHIP-GATING VIOLATION (bare flagship assertion): ${file}:${line_no}:${line}" >&2
  flagship_violations=$((flagship_violations + 1))
done < <(grep -rnE --include='*.tex' --include='*.md' "${FLAGSHIP_PATTERN}" "${SPECS_DIR}" "${FORMAL_DIR}" || true)

if [ "${flagship_violations}" -ne 0 ]; then
  echo "FAIL: ${flagship_violations} bare flagship assertion(s) — a flagship rung printed without its blocked/gated marker while its condition set is open (see p4_claim_adjudication.md)." >&2
  exit 1
fi

echo "PASS: no unqualified 99% tolerance spellings, and no bare flagship assertions, in the AFT specs/formal corpus."
