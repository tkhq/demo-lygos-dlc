# TVC app and deployment config

## Current app: `lygos-dlc-demo-v2`

Identifiers for the dev deployment. These are identifiers, not secrets.

| | |
| --- | --- |
| App ID | `35e626e0-958b-48de-8ed9-e57dbf08fe41` |
| Operator ID | `0066f25e-cccc-4f4a-885c-c6d08a4006f3` |
| Manifest Set ID | `db587844-763c-4a9e-900f-4ce972d5c31a` |
| Org | Connor Dev (`76043c53-0cae-4ab9-882c-d373611432c4`), api.dev.turnkey.engineering |
| App URL | https://app-35e626e0-958b-48de-8ed9-e57dbf08fe41.apps.tvc-dev.turnkey.engineering |
| Egress | enabled — required for the Blockstream lookup |
| Debug mode | **disabled**, so attestation PCRs are real |

Note the host is `apps.tvc-dev.turnkey.engineering`, not the `tvc.dev.turnkey.engineering`
pattern some older runbooks quote. Take the domain from `tvc app list` rather than assuming it.

Requires `tvc` >= 0.14.0. Older CLIs name these fields differently (`externalConnectivity`,
`debugMode`) and have no app-level debug flag at all, so an app created with one gets working
egress but can never serve debug logs — and neither flag can be changed after creation.

## Two caveats on what the attestation currently proves

**1. Debug mode is off, but nothing verifies the PCRs yet.** Turning debug off means the
attestation document now carries real PCR values instead of zeros, so the *claim* "this verdict
came from the approved binary" is true. But the demo does not yet check it: the in-browser proof
verifies only that the holder of the published key signed the payload. It never fetches the
attestation document, never checks the PCRs against the approved manifest, and never confirms the
signing key is the one the document attests to. Until that exists, the green checkmark would look
identical on a debug deployment — so treat it as "signature verified", not "attestation verified".

`qos_nsm` 0.13 has everything needed to close this (`Nsm::nsm_process_request` for the document,
`/qos.manifest` for the expected PCRs, `nitro::verify_attestation_doc_against_manifest_live` for
the comparison, and a hardcoded AWS root CA). It compiles on macOS and fails cleanly off-enclave,
so an `/attestation` endpoint can degrade to "unavailable" locally. The one untested unknown is
whether the pivot process can reach `/dev/nsm`.

**2. The quorum key is a shared bootstrap key, independent of debug mode.** `tvc deploy
provisioning-details` reports *"uses the insecure bootstrap quorum key and does not support manual
provisioning"* on this app exactly as it did on the debug one — so this is not a debug-mode
artifact. Every app created from `tvc app init` in this org carries the same pre-filled
`quorumPublicKey`, and `shareSetParams` is null, meaning no per-app quorum key was provisioned via
the share-set flow.

This does not undermine this app's proofs, because it signs with the **ephemeral** key, which is
generated inside the enclave at boot and is what the attestation document binds to. But nothing
relying on the quorum key should be considered secure here, and a production posture would need
the share-set provisioning flow.

## Superseded apps

Both should be deleted once nobody is pointing at them, so no one demos the wrong URL.

| App | ID | Why it was replaced |
| --- | --- | --- |
| `lygos-dlc-demo` | `b7e80e58-…` | created by tvc 0.7.0, which silently omits the app-level debug flag; deleted |
| `lygos-dlc-verify` | `12af0180-…` | debug mode enabled, which zeroes attestation PCRs and permanently marks the app's quorum key insecure |

Debug-mode deployments cannot be undone by redeploying without debug: running even one marks the
app's quorum key insecure for good, which is why the cutover needed a whole new app rather than a
new deployment.

## Deploying

```sh
OPERATOR_ID=0066f25e-cccc-4f4a-885c-c6d08a4006f3 ./deploy-latest.sh
```

`deploy-latest.sh` takes `pivotContainerImageUrl` and `expectedPivotDigest` from the latest
`stagex` run. Do not fill them in by hand: only a reproducible StageX build produces values that
match what the enclave will actually measure, and a stale digest fails inside the enclave rather
than at create time.

Two things that cost time the first time round:

- **Approval does not promote a deployment.** After `tvc deploy approve`, the previous deployment
  keeps serving traffic until `tvc app set-live-deploy --deploy-id <new>`. `/health` returns 200
  throughout, so this looks exactly like a successful deploy of code that is not running. Confirm
  the new build is live by checking for something only it returns, not by checking health.
- **A non-debug deployment takes longer to come up** — about 100 seconds here versus 20 for a
  debug one, returning 404 until it is ready. That is not a failure; give it a few minutes before
  reaching for debug logs (which this app deliberately cannot serve).
