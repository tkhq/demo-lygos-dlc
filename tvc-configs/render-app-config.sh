#!/usr/bin/env bash
# Render an app config for `tvc app create`, substituting the operator public key
# from local.env into the committed template.
#
#   ENV=dev ./tvc-configs/render-app-config.sh
#   tvc app create --config-file tvc-configs/app.dev.local.json
#
# The rendered file is gitignored. Doing this with a script rather than by hand
# matters because the operator key is 130 characters of hex, and this repo has
# already been bitten once by a hand-copied hex string with two bytes transposed.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
ENV="${ENV:-prod}"

if [ ! -f "$here/local.env" ]; then
  echo "no $here/local.env; copy local.env.example to local.env and fill it in" >&2
  exit 1
fi
# shellcheck disable=SC1091
. "$here/local.env"

case "$ENV" in
  prod) template="$here/app.json";     out="$here/app.local.json";     key="${PROD_OPERATOR_PUBKEY:-}" ;;
  dev)  template="$here/app.dev.json"; out="$here/app.dev.local.json"; key="${DEV_OPERATOR_PUBKEY:-}" ;;
  *)    echo "ENV must be prod or dev, got '$ENV'" >&2; exit 1 ;;
esac

test -n "$key" || { echo "no operator public key for ENV=$ENV; set it in local.env" >&2; exit 1; }

jq --arg key "$key" '.manifestSetParams.newOperators[0].publicKey = $key' "$template" > "$out"
echo "$out"
