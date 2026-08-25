# TVC app and deployment config

> **Demonstration only.** This app is unsupported, unaudited, and can be redeployed or removed
> without notice. Running on production infrastructure does not make the demo production-ready. The
> repository README lists everything it does not guarantee.

Two environments, each with its own org, app, and config files.

| | Production | Dev |
| --- | --- | --- |
| Config | `app.json`, `deploy.json` | `app.dev.json`, `deploy.dev.json` |
| API | `https://api.turnkey.com` | `https://api.dev.turnkey.engineering` |
| App URL | `https://app-<APP_ID>.app.turnkey.cloud` | `https://app-<APP_ID>.apps.tvc-dev.turnkey.engineering` |
| Debug mode | Disabled | Disabled |
| Purpose | What customers see | Where changes get tried first |

Take the app URL from `tvc app list` rather than assuming it. The two environments use different
hostname patterns, and older runbooks quote a dev pattern that is no longer right.

## Identifiers live in local.env

The committed configs carry `REPLACE_FROM_LOCAL_ENV_*` placeholders where an org, app, operator or
manifest-set id would go. The real values live in `local.env`, which is gitignored.

```sh
cp tvc-configs/local.env.example tvc-configs/local.env
# fill it in, then
ENV=dev ./tvc-configs/render-app-config.sh   # writes app.dev.local.json, also gitignored
```

None of it is secret. The operator entries are public keys, and the ids are identifiers rather than
credentials. They are kept out of the repo because this repo is public and none of it says anything
about the demo, only about who deploys it. Anyone running their own copy fills in their own values,
and nothing here is needed to build the app or read the code.

Requires `tvc` >= 0.14.0. Older CLIs name these fields differently (`externalConnectivity`,
`debugMode`) and have no app-level debug flag at all. An app created with one gets working egress
but can never serve debug logs, and neither flag can be changed after creation.

## Creating an app

`enableEgress` and debug mode cannot be added to an app later, so both have to be right at creation.

```sh
tvc login                                            # point at the right org first
ENV=prod ./tvc-configs/render-app-config.sh
tvc app create --config-file tvc-configs/app.local.json
```

Record the app id, operator id and manifest set id it prints into `local.env`.

Never enable debug mode on an app you intend to show. Debug zeroes the attestation PCRs and
permanently marks the app's quorum key insecure, and neither can be undone by a later deployment.
Recovering means creating a new app and a new URL.

## Deploying

The org differs per environment, so `tvc login` has to be pointed at the right one first. The active
org lives in `~/.config/turnkey/tvc.config.toml`.

```sh
ENV=prod ./tvc-configs/deploy-latest.sh
ENV=dev  ./tvc-configs/deploy-latest.sh
```

`deploy-latest.sh` takes `pivotContainerImageUrl` and `expectedPivotDigest` from the latest `stagex`
run and writes a rendered config to a gitignored `.rendered.<env>.json`, leaving the committed
template alone. Do not fill the digests in by hand. Only a reproducible StageX build produces values
that match what the enclave will actually measure, and a stale digest fails inside the enclave
rather than at create time.

Deploy to production from a `main` build rather than a `pr-N` tag, so the running code is something
that was merged and reviewed.

Three things that cost time the first time round:

1. **Approval does not promote a deployment.** After `tvc deploy approve`, the previous deployment
   keeps serving traffic until `tvc app set-live-deploy --deploy-id <new>`. `/health` returns 200
   throughout, so this looks exactly like a successful deploy of code that is not running. Confirm
   the new build is live by checking for something only it returns, not by checking health.
2. **`set-live-deploy` refuses until the new deployment has healthy replicas**, reporting `zero
   healthy replicas`. That took about 80 seconds on dev. It is a useful guard rather than an error.
3. **A non-debug deployment takes longer to come up**, about 100 seconds on dev versus 20 for a debug
   one, returning 404 until it is ready. That is not a failure. Give it a few minutes before
   reaching for debug logs, which these apps deliberately cannot serve.

Right after a promotion, one request may still hit a draining replica and answer from the old build.
Give a redeploy a minute to settle before trusting the first response.

## Two caveats on what the attestation proves

Both apply on production exactly as they do on dev. A production URL changes nothing about them.

**1. Debug mode is off, but nothing ties the signing key to attested code.** Turning debug off means
a boot proof for this enclave would carry real PCRs instead of zeros. The demo stops at the app
proof: it verifies that the enclave's key signed the verdict, not that the key belongs to an enclave
running this code. Pairing the app proof with a boot proof is the missing step, and the green check
in the UI must not be described as proving attestation until that exists.

Do it through Turnkey's own flow. Match the app proof's `publicKey` against a valid boot proof's
`public_key` field, using [`turnkey_proofs`](https://github.com/tkhq/rust-sdk/tree/main/proofs) or
the [TypeScript verifier](https://github.com/tkhq/sdk/tree/main/packages/crypto/src/proof.ts).

An earlier attempt had the app call the Nitro Secure Module to mint its own document. That was the
wrong mechanism and was reverted. The boot proof already exists and already binds the ephemeral key,
and an enclave attesting to itself establishes nothing regardless.

**2. The quorum key is a shared bootstrap key.** On dev, `tvc deploy provisioning-details` reports
*"uses the insecure bootstrap quorum key and does not support manual provisioning"*. Every app
created from `tvc app init` carries the same pre-filled `quorumPublicKey`, and `shareSetParams` is
null, so no per-app quorum key was provisioned through the share-set flow. Check whether production
behaves the same way once the app exists.

This does not undermine the app's proofs, because it signs with the **ephemeral** key, which is
generated inside the enclave at boot and is what the attestation document binds to. Nothing relying
on the quorum key is secure here, and a production posture would need the share-set provisioning
flow.
