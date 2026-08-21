# TVC app and deployment config

## This app is for iteration, not for demoing

> **The current app runs in debug mode, so its attestation proves nothing.** Debug-mode
> deployments zero the attestation PCRs, which means a proof signature shows only that
> *something* holding the key signed the payload — not that the approved binary produced it.
> That guarantee is the entire reason this service runs in an enclave, so a demo given on this
> app would be making a claim it cannot support.
>
> The taint is also permanent: running even one debug deployment marks the app's quorum key
> insecure for good, and turning debug off for a later deployment does not undo it.
>
> **Before showing this to anyone, create a fresh app with
> `dangerousEnableDebugModeDeployments: false` and deploy with `dangerousDeployDebugMode: false`,
> then confirm the attestation PCRs are non-zero.** Keep debug on only while iterating, where
> being able to read `tvc deploy debug-logs` is worth more than an attestation nobody is
> checking yet.

Identifiers for the current (debug) app. These are identifiers, not secrets.

| | |
| --- | --- |
| App ID | `12af0180-bc5c-4079-9142-ca4688611e40` |
| Operator ID | `0066f25e-cccc-4f4a-885c-c6d08a4006f3` |
| Manifest Set ID | `5ca0c93f-7a39-4780-a7c7-c2e77bfd4ad9` |
| Org | Connor Dev (`76043c53-0cae-4ab9-882c-d373611432c4`), api.dev.turnkey.engineering |
| App URL | https://app-12af0180-bc5c-4079-9142-ca4688611e40.apps.tvc-dev.turnkey.engineering |

Note the host is `apps.tvc-dev.turnkey.engineering`, not the `tvc.dev.turnkey.engineering`
pattern some older runbooks quote. Take the domain from `tvc app list` rather than assuming it.

`enableEgress` is true and **cannot be changed after creation** — it is what lets the enclave
reach Blockstream. Debug mode is two flags that both have to be set: the app must permit it
(`dangerousEnableDebugModeDeployments`, also fixed at creation) and the deployment must ask for
it (`dangerousDeployDebugMode`). Set the app flag to `false` for anything you intend to show.

Requires `tvc` >= 0.14.0. Older CLIs use different field names for these
(`externalConnectivity`, `debugMode`) and silently omit the app-level debug flag entirely, so an
app created with one gets working egress but can never serve debug logs.

## Deploying

```sh
OPERATOR_ID=0066f25e-cccc-4f4a-885c-c6d08a4006f3 ./deploy-latest.sh
```

`deploy-latest.sh` takes `pivotContainerImageUrl` and `expectedPivotDigest` from the latest
`stagex` run. Do not fill them in by hand: only a reproducible StageX build produces values that
match what the enclave will actually measure, and a stale digest fails inside the enclave rather
than at create time.
