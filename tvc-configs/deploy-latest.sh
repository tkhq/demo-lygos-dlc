#!/usr/bin/env bash
# One pass of the deploy loop: wait for the stagex build, read its digests, deploy them.
#
# The two digests are only ever taken from a CI run. Hand-editing them means deploying
# something other than the code you just pushed, and the failure shows up later, inside
# the enclave, as a validation error rather than here.
#
#   ENV=dev  ./tvc-configs/deploy-latest.sh
#   ENV=prod ./tvc-configs/deploy-latest.sh
#
# App and operator ids come from tvc-configs/local.env, which is gitignored. Copy
# local.env.example to local.env and fill it in first. The two environments live in
# different orgs, so `tvc login` has to already point at the matching one.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
REPO="${REPO:-tkhq/lygos-dlc-demo}"
ENV="${ENV:-prod}"

if [ -f "$here/local.env" ]; then
  # shellcheck disable=SC1091
  . "$here/local.env"
else
  echo "no $here/local.env; copy local.env.example to local.env and fill it in" >&2
  exit 1
fi

case "$ENV" in
  prod) CONFIG="${CONFIG:-$here/deploy.json}"
        APP_ID="${APP_ID:-${PROD_APP_ID:-}}"
        OPERATOR_ID="${OPERATOR_ID:-${PROD_OPERATOR_ID:-}}" ;;
  dev)  CONFIG="${CONFIG:-$here/deploy.dev.json}"
        APP_ID="${APP_ID:-${DEV_APP_ID:-}}"
        OPERATOR_ID="${OPERATOR_ID:-${DEV_OPERATOR_ID:-}}" ;;
  *)    echo "ENV must be prod or dev, got '$ENV'" >&2; exit 1 ;;
esac

test -n "$APP_ID" || { echo "no app id for ENV=$ENV; set it in local.env" >&2; exit 1; }
test -n "$OPERATOR_ID" || { echo "no operator id for ENV=$ENV; set it in local.env" >&2; exit 1; }

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

# Render to a gitignored file rather than mutating the committed template, so the app id
# and the digests never end up in a commit.
rendered="$here/.rendered.$ENV.json"
jq --arg app "$APP_ID" --arg img "$image" --arg dg "$pivot" \
  '.appId = $app | .pivotContainerImageUrl = $img | .expectedPivotDigest = $dg' \
  "$CONFIG" > "$rendered"

tvc deploy create --config-file "$rendered" | tee /tmp/tvc-create.out
# Match the labelled line. Taking the first UUID in the output picks up the app id from
# the "Creating deployment for app '<uuid>'" banner instead.
deploy_id=$(grep -oE 'Deployment ID: [0-9a-f-]{36}' /tmp/tvc-create.out | head -1 | awk '{print $3}')
test -n "$deploy_id" || { echo "could not find a Deployment ID in tvc deploy create output"; exit 1; }
echo "deploy id: $deploy_id"

tvc deploy approve --deploy-id "$deploy_id" --operator-id "$OPERATOR_ID" --dangerous-skip-interactive
tvc deploy status --deploy-id "$deploy_id"

# Approval does not promote an app that already has a live deployment. The previous one
# keeps serving traffic, and /health returns 200 from it, until the new one is made live.
# The very first deployment on a new app is promoted automatically.
echo
echo "approved. unless this was the app's first deployment, promote it once replicas are healthy:"
echo "  tvc app set-live-deploy --deploy-id $deploy_id"
