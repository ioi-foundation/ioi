#!/usr/bin/env bash
# Commission the owner-authorized fresh gpt-daybreak-blue-latest reviewer against
# one immutable candidate tag, in a clean disposable clone, with review output
# written outside the clone. Never pushes, never touches the primary checkout.
set -euo pipefail
TAG="${1:?tag}"
CODEX=/home/heathledger/.vscode/extensions/openai.chatgpt-26.5901.22334-linux-x64/bin/linux-x86_64/codex
PROMPT_TEMPLATE="${2:?prompt template}"
SRC=/home/heathledger/Documents/ioi/repos/ioi
ROOT="$(mktemp -d /tmp/ioi-m17q-r2-daybreak.XXXXXX)"
CLONE="${ROOT}/review-clone"
OUT="${ROOT}/review-output"
mkdir -p "${OUT}"
git clone --quiet --no-hardlinks --no-checkout "${SRC}" "${CLONE}"
cd "${CLONE}"
git fetch --quiet --force --tags origin
TYPE="$(git cat-file -t "refs/tags/${TAG}")"
OBJ="$(git rev-parse "refs/tags/${TAG}")"
PEELED="$(git rev-parse "refs/tags/${TAG}^{}")"
git checkout --quiet --detach "${PEELED}"
STATUS="$(git status --short --branch)"
{
  echo "tag=${TAG}"; echo "object_type=${TYPE}"; echo "tag_object=${OBJ}"; echo "peeled_commit=${PEELED}"
  echo "status=${STATUS}"; echo "clone=${CLONE}"; echo "output=${OUT}"; echo "started_utc=$(date -u +%FT%TZ)"
} | tee "${OUT}/immutable-preflight.txt"
sed -e "s#TAG_PLACEHOLDER#${TAG}#g" -e "s#OUTPUT_DIR_PLACEHOLDER#${OUT}#g" "${PROMPT_TEMPLATE}" > "${OUT}/commission-prompt.md"
cd "${CLONE}"
"${CODEX}" exec -m gpt-daybreak-blue-latest --ephemeral -s workspace-write --add-dir "${OUT}" -C "${CLONE}" \
  -o "${OUT}/reviewer-last-message.md" - < "${OUT}/commission-prompt.md" > "${OUT}/codex-exec.log" 2>&1
echo "exit=$?" | tee -a "${OUT}/immutable-preflight.txt"
echo "review output: ${OUT}"
