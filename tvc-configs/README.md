# TVC app and deployment config

Identifiers for the dev deployment of this app. These are identifiers, not secrets.

| | |
| --- | --- |
| App ID | `12af0180-bc5c-4079-9142-ca4688611e40` |
| Operator ID | `0066f25e-cccc-4f4a-885c-c6d08a4006f3` |
| Manifest Set ID | `5ca0c93f-7a39-4780-a7c7-c2e77bfd4ad9` |
| Org | Connor Dev (`76043c53-0cae-4ab9-882c-d373611432c4`), api.dev.turnkey.engineering |
| App URL | https://app-12af0180-bc5c-4079-9142-ca4688611e40.apps.tvc-dev.turnkey.engineering |

Note the host is `apps.tvc-dev.turnkey.engineering`, not the `tvc.dev.turnkey.engineering`
pattern some older runbooks quote. Take the domain from `tvc app list` rather than assuming it.

`enableEgress` and `dangerousEnableDebugModeDeployments` are both true and **cannot be changed
after creation** — egress is what lets the enclave reach Blockstream, and without the debug flag
`tvc deploy debug-logs` is unavailable, which is the only way to see why an enclave failed to
boot. Debug mode also has to be set per deployment (`dangerousDeployDebugMode`), and needs both.

Requires `tvc` >= 0.14.0. Older CLIs use different field names for these
(`externalConnectivity`, `debugMode`) and silently omit the app-level debug flag entirely.

## Deploying

```sh
OPERATOR_ID=0066f25e-cccc-4f4a-885c-c6d08a4006f3 ./deploy-latest.sh
```

`deploy-latest.sh` takes `pivotContainerImageUrl` and `expectedPivotDigest` from the latest
`stagex` run. Do not fill them in by hand: only a reproducible StageX build produces values that
match what the enclave will actually measure, and a stale digest fails inside the enclave rather
than at create time.
