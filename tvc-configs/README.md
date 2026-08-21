# TVC app and deployment config

Identifiers for the dev deployment of this app. These are identifiers, not secrets.

| | |
| --- | --- |
| App ID | `b7e80e58-21b9-4480-8ba1-860bef4a016f` |
| Operator ID | `0066f25e-cccc-4f4a-885c-c6d08a4006f3` |
| Manifest Set ID | `5315fd1b-00f9-496b-8d78-12f4c6f860d7` |
| Org | Connor Dev (`76043c53-0cae-4ab9-882c-d373611432c4`), api.dev.turnkey.engineering |
| App URL | https://app-b7e80e58-21b9-4480-8ba1-860bef4a016f.tvc.dev.turnkey.engineering |

`externalConnectivity` is `true` on the app, which the Blockstream lookup needs and which
cannot be changed after creation. `debugMode` is per-deployment in `deploy.json`, so it can be
turned off for a later deployment without recreating the app.

## Deploying

```sh
OPERATOR_ID=0066f25e-cccc-4f4a-885c-c6d08a4006f3 ./deploy-latest.sh
```

`deploy-latest.sh` takes `pivotContainerImageUrl` and `expectedPivotDigest` from the latest
`stagex` run. Do not fill them in by hand: only a reproducible StageX build produces values that
match what the enclave will actually measure, and a stale digest fails inside the enclave rather
than at create time.
