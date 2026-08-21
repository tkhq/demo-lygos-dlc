#!/usr/bin/env bash
# One pass of the deploy loop: wait for the stagex build, read its digests, deploy them.
#
# The two digests are only ever taken from a CI run. Hand-editing them means deploying
# something other than the code you just pushed, and the failure shows up later, inside
# the enclave, as a validation error rather than here.
set -euo pipefail

REPO="${REPO:-tkhq/lygos-dlc-demo}"
CONFIG="${CONFIG:-$(dirname "$0")/deploy.json}"
OPERATOR_ID="${OPERATOR_ID:?set OPERATOR_ID (see README.md in this directory)}"

run_id=$(gh run list -R "$REPO" -w stagex -L 1 --json databaseId -q '.[0].databaseId')
echo "watching stagex run $run_id"
gh run watch -R "$REPO" "$run_id" --exit-status

# The log contains both the workflow's echoed commands and their output, so match only
# lines carrying a resolved value. Grepping the label alone picks up the echo line first
# and yields a literal "${container_url}".
log=$(gh run view "$run_id" -R "$REPO" --log | sed 's/\x1b\[[0-9;]*m//g')
image=$(printf '%s' "$log" | grep -oE 'Container Image URL: ghcr\.io/[^[:space:]]+@sha256:[0-9a-f]{64}' \
  | head -1 | sed 's/.*Container Image URL: //')
pivot=$(printf '%s' "$log" | grep -oE 'Expected Executable Digest: [0-9a-f]{64}' \
  | head -1 | sed 's/.*Expected Executable Digest: //')

test -n "$image" || { echo "no image URL in run log"; exit 1; }
test -n "$pivot" || { echo "no pivot digest in run log"; exit 1; }
echo "image: $image"
echo "pivot: $pivot"

jq --arg img "$image" --arg dg "$pivot" \
  '.pivotContainerImageUrl = $img | .expectedPivotDigest = $dg' \
  "$CONFIG" > "$CONFIG.tmp" && mv "$CONFIG.tmp" "$CONFIG"

tvc deploy create --config-file "$CONFIG" | tee /tmp/tvc-create.out
deploy_id=$(grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' /tmp/tvc-create.out | head -1)
echo "deploy id: $deploy_id"

tvc deploy approve --deploy-id "$deploy_id" --operator-id "$OPERATOR_ID" --dangerous-skip-interactive
tvc deploy status --deploy-id "$deploy_id"
