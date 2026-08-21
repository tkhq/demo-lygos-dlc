# Lygos DLC verification in a TVC enclave

A Rust service that runs inside a [Turnkey Verifiable Cloud](https://docs.turnkey.com) enclave and answers one question about a Lygos loan: **is this contract sound, and is its collateral actually locked on Bitcoin?**

It verifies the contract the way Lygos's own [`dlc-verify`](https://github.com/LygosLabs/dlc-verify) does — message structure, the oracle's announcement signature, and every CET adaptor signature — then looks the collateral transaction up on Bitcoin over enclave egress, and signs the combined verdict with a key sealed to the approved binary.

## Why this is a rewrite rather than a port

`dlc-verify` is Node, and its cryptographic core is [DDK](https://www.npmjs.com/package/@bennyblader/ddk-ts), a prebuilt native addon. TVC deployments are a single statically linked binary whose SHA-256 is reviewed and approved before it can run, so a Node runtime plus an opaque `.node` binary does not fit: the digest would cover a launcher script rather than the code doing the verifying, which is the entire point of the attestation.

So the verification is reimplemented here in Rust on [`rust-dlc`](https://github.com/p2pderivatives/rust-dlc). Three things had to be worked out to make that produce the same answers as DDK. Each is load-bearing, and each is covered by a test that fails loudly if it regresses.

### 1. node-dlc writes a field `rust-dlc` does not read

Lygos serializes with `node-dlc`, which appends an optional `dlc_input` to every funding input (`0x00` absent / `0x01` present, then two pubkeys and a contract id) so a DLC can be funded by another DLC's output. `rust-dlc` 0.8's `FundingInput` has no such field.

The dangerous part is that this does not reliably fail. `rust-dlc` writes no per-element framing inside a vector, so on a one-input offer the extra byte shifts everything after it and the parse *succeeds* with garbage — we measured a `fee_rate_per_vb` of 5,263,947,935,078,877,696 where the real value was 3. Every downstream number, including the fund transaction and therefore the adaptor signatures, would be computed from that. `dlc/codec.rs` decodes offers itself, and a test asserts the upstream parser disagrees, so nobody is tempted to "simplify" it back.

### 2. `rust-dlc` validates oracle announcements with the wrong hash

`OracleAnnouncement::validate` hashes the oracle event with a plain SHA-256 over its non-TLV encoding. The DLC specification — and every announcement Lygos produces — uses a BIP340 tagged hash over the TLV encoding. Using the upstream check reports valid announcements as invalid. `dlc/verify.rs` does the tagged-hash check instead.

### 3. Lygos loans are single-funded, which `rust-dlc` refuses to build

The borrower supplies all the collateral and all the inputs; the lender supplies neither. `rust-dlc`'s `create_dlc_transactions` rejects this, because it charges each party for its own fees and the lender has no inputs to charge. DDK handles it, which is why `dlc-verify` needs DDK at all.

`dlc/txs.rs` reimplements that construction. Three details differ from a symmetric DLC, all derived by matching DDK's output byte for byte:

- the borrower alone bears the **whole** fund-transaction base weight, not half;
- the CET fee is **prepaid into the fund output**, so it holds `total_collateral + cet_fee` and each CET pays the full unreduced payout;
- a CET carries one output per non-dust payout, so an all-or-nothing loan CET has exactly one.

This has to be exact — an adaptor signature commits to the CET's sighash, so one wrong byte invalidates every signature. For the sample contract that means a fund output of 11,470 sat (10,000 collateral + 1,470 prepaid CET fee), a fund fee of 2,490 sat, and fund txid `15659a28…604274`, which is what DDK produces and what the tests assert.

## Two use cases

The same verification serves two callers who need different things proven. `profile` on the
request decides what is allowed to block the verdict; the cryptography is identical either way.

### Institutional lender

Lygos hands the lender the offer, accept and sign messages. The lender supplies the terms it
agreed to — lender key, oracle key and event id, repayment and liquidation destinations, refund
address and locktime, maturity, collateral, payouts. The enclave confirms the contract is
cryptographically sound **and** that it encodes those terms, and returns a decoded report the
lender can rely on before advancing funds. No chain lookup: the collateral need not be posted yet.

### Morpho Midnight

The same verification, plus proof that the Bitcoin collateral is actually funded. The enclave
reconstructs the expected funding transaction from the DLC itself, then queries Bitcoin over
egress to confirm it is on chain with enough confirmations. The output is a signed attestation
the Midnight contracts require before minting a collateral representation, which is what lets the
guardian network keep securing the lender key without also acting as the verification quorum.

The response carries a `termsDigest` — a hash over the expected terms — so the EVM side can bind
minting to exactly the terms that were verified rather than re-deriving them and hoping they agree.

## What it checks

| Check | Meaning |
| --- | --- |
| Message structure | The offer, accept, and sign messages decode |
| Oracle announcement signature | The oracle really committed to this event |
| CET adaptor signatures | Each payout can only be claimed with the oracle's attestation for that outcome |
| Refund signatures | Both parties can recover funds if the oracle never attests |
| Sign contract id | The sign message refers to the contract the offer and accept imply |
| Oracle event id | The contract references the event the caller expects |
| Expected terms | Keys, destinations, amounts, locktimes and payouts match what was agreed |
| On-chain funding | The collateral transaction is in a block with enough confirmations |

Each check reports one of four statuses, and the difference between the last three matters:

- `pass` — checked and matched
- `fail` — checked and did not match
- `not_checked` — the caller supplied no expectation, so nothing was compared
- `not_verifiable` — no verdict is possible (see the event-id note below)

A `required` check only satisfies the verdict on `pass`. Treating `not_checked` as success is
exactly how a gate ends up approving something it never verified, so an expectation you did not
state can never be mistaken for one that was met — and supplying no terms at all fails outright
rather than reporting a green built on nothing.

`failureReasons` gives a caller a small set to branch on (`MALFORMED_INPUT`,
`DLC_VERIFICATION_FAILED`, `MISMATCH_EXPECTED_VS_PARSED`, `TX_NOT_FOUND`,
`EXPLORER_REQUEST_FAILED`, `CHECK_NOT_VERIFIABLE`), and `blockingChecks` names precisely which
required checks did not pass. A contract that is cryptographically perfect but encodes different
terms fails as a mismatch, not as broken cryptography — those are different problems.

### The oracle event id, and what is a placeholder

The event id ties the DLC to a *specific* loan, so it is worth checking two ways:

- **Exact match** against an id the caller expects. This is real and works today.
- **Recomputation** from the loan parameters, which proves the DLC encodes the terms the lender
  believes it does without trusting any id handed to them.

**The recomputation here uses a documented placeholder, not Lygos's derivation.** Their event ids
are `loan-matured-` plus a 32-byte hash, and that hash is not derived from anything inside the
DLC, so it is computed over off-chain loan parameters whose encoding is not published — three
sample contracts are not enough to recover it. Rather than guess, `event_id.rs` reports
`not_verifiable` and never a pass or a fail, so it cannot produce a misleading green or blame the
contract for our missing rule. It still earns its place: every loan parameter affects the derived
id, so altering any term visibly changes it, which is the whole argument for the real check.
Substituting Lygos's derivation is a one-function change.

### EVM terms are attested, not verified

`expected.evm` is echoed into the report and the signed payload as `informational`, labelled
`not verified here`. This service verifies the Bitcoin and DLC side; the EVM side binds to the
same values via the `termsDigest`. Reporting them as checked would be a claim we cannot support.

## API

| Endpoint | Purpose |
| --- | --- |
| `GET /health` | Liveness |
| `GET /app_key` | The enclave's public key, for verifying proofs |
| `POST /dlc/verify` | Contract and expected terms. No network access, fully deterministic |
| `POST /dlc/verify_loan` | The same, **and** confirm the collateral on Bitcoin over egress |
| `GET /metrics` | Prometheus metrics |

```sh
curl -X POST "$BASE/dlc/verify_loan" -H 'content-type: application/json' -d '{
  "profile": "morpho_midnight",
  "offerHex": "a71a…", "acceptHex": "a71c…", "signHex": "a71e…",
  "network": "regtest",
  "expected": {
    "lenderPubkey": "031d7709…", "oraclePubkey": "8731249d…",
    "oracleEventId": "loan-matured-1da042f2…",
    "totalCollateralSats": 10000,
    "repayment":   { "address": "bcrt1q6tas5…", "sats": 10000 },
    "liquidation": { "address": "bcrt1qup6w2…" },
    "refund":      { "address": "bcrt1q6tas5…", "locktime": 1790352000 },
    "cetLocktime": 1781734876,
    "outcomes": [ { "label": "repaid", "offererSats": 10000, "accepterSats": 0 } ],
    "loanTerms": { "loanId": "LYG-2026-001", "repaymentAmount": "52500" },
    "evm": { "position": "morpho-midnight-42", "collateralSats": 10000 }
  },
  "btcTxid": "dcf70d60…", "bitcoinNetwork": "testnet"
}'
```

`profile` is `institutional_lender` (the default) or `morpho_midnight`. Everything under
`expected` is optional, but a request with no expectations at all fails rather than reporting a
verdict it cannot support.

Omit `btcTxid` and the app checks the fund transaction it derived from the contract, which is the production behaviour. Omit `expectedOraclePubkey` and the oracle-identity check is skipped rather than assumed.

Every response carries a `proof`: the enclave's signature over the exact JSON of the verdict.

```jsonc
{
  "status": "verified",
  "profile": "morpho_midnight",
  "dlc": { "adaptorSigsValid": true, "adaptorValidCount": 5, "fundTxid": "15659a28…" },
  "bitcoin": { "confirmed": true, "blockHeight": 5124341, "confirmations": 430 },
  "checks": [
    { "id": "cet_adaptor_signatures", "status": "pass", "severity": "required" },
    { "id": "liquidation_address", "status": "pass", "severity": "required",
      "expected": "bcrt1qup6w2…", "actual": "bcrt1qup6w2…" },
    { "id": "oracle_event_id_recomputed", "status": "not_verifiable",
      "severity": "informational", "detail": "derivation=DEMO_PLACEHOLDER…" }
  ],
  "blockingChecks": [],
  "termsDigest": "eeab2237…",
  "failureReasons": [],
  "proof": { "algorithm": "P256", "publicKey": "04…", "payload": "{…}", "signature": "…" }
}
```

To check a proof: `publicKey` is two concatenated uncompressed P-256 points, and the **second** is the signing key. The signature is raw `r||s`, and the signed message is `payload` verbatim. `frontend/index.html` does this with WebCrypto in about fifteen lines.

## Running locally

```sh
make lint
make test
make run      # 127.0.0.1:44020
```

Then open `frontend/index.html`. It points at `http://127.0.0.1:44020` by default; to aim it elsewhere:

```sh
cd frontend && TVC_APP_URL=https://app-<APP_ID>.apps.tvc-dev.turnkey.engineering ./build.sh
```

`make run` generates throwaway keys in `/tmp/tvc-template-local-enclave`, so proofs verify against a key that is *not* attested. Local runs check routing and verification logic; only a deployed enclave demonstrates the attestation.

> **Debug mode voids the attestation.** A deployment created with `dangerousDeployDebugMode`
> zeroes the attestation PCRs, so a proof signature no longer shows that the *approved binary*
> produced the verdict — only that something holding the key signed it. Running one debug
> deployment also marks the app's quorum key insecure permanently. Use debug mode while
> iterating, and deploy to an app created with `dangerousEnableDebugModeDeployments: false`
> before demonstrating the attestation to anyone. See `tvc-configs/README.md`.

### About the demo transaction id

The sample contracts are regtest and testnet fixtures that were never broadcast, so their own fund transactions cannot be looked up on a public explorer. The frontend prefills a real confirmed testnet3 transaction so the on-chain step genuinely runs. Because that transaction has nothing to do with the sample contract, `fundingOutputMatch` is `false` — reported for information, not counted as a failure. Clearing the field makes the app fall back to the contract's own derived `fundTxid`, which correctly reports `TX_NOT_FOUND` for a contract that was never broadcast.

## Deploying

The deploy config pins an image digest and the SHA-256 of the binary inside it, and only a reproducible StageX build produces those, so every deployment goes through CI.

One-time, noting that `enableEgress` and debug mode **cannot be added to an app later**:

```sh
cargo install tvc --locked   # 0.14.0 or newer, see below
tvc login --api-base-url https://api.dev.turnkey.engineering
tvc app create --config-file tvc-configs/app.json   # record the app id and operator id
```

`tvc-configs/app.json` targets **tvc >= 0.14.0**. An older CLI names these fields differently
(`externalConnectivity` for egress, `debugMode` on the deployment) and has no app-level debug
field at all, so creating the app with one silently produces an app that egress works on but
that can never serve debug logs — and neither flag can be changed afterwards. Check with
`cargo install --list | grep tvc` before creating anything.

Then per pass: `make lint test`, push, wait for the `stagex` workflow, take **Container Image URL** and **Expected Executable Digest** from its summary, and deploy them.

```sh
OPERATOR_ID=<operator-id> ./tvc-configs/deploy-latest.sh
```

The app URL is stable at `https://app-<APP_ID>.apps.tvc-dev.turnkey.engineering`, so only the deployment changes. Delete the superseded deployment once the new one serves traffic, otherwise it is ambiguous which build answered a request.

Worth knowing:

- A newly created `ghcr.io/tkhq/dlc-verify` package is **private**, and the enclave cannot pull it. Make it public or pass `--pivot-pull-secret`.
- `expectedPivotDigest` is the digest of the binary *inside* the image, not the image digest. Confusing the two produces a deployment that fails inside the enclave rather than at create time.
- Always pin `@sha256:`. A bare `:pr-N` tag moves with every push, so the manifest you approve stops describing the code you meant to test.
- Debug logs (`tvc deploy debug-logs --poll`) need debug mode on both the app and the deployment.
- A cold StageX cache can run close to the 60-minute timeout. A slow build is not a hung build.

## Layout

```
crates/dlc-verify/src/
  dlc/codec.rs     node-dlc wire decoding, including the dlc_input extension
  dlc/txs.rs       single-funded fund, CET and refund reconstruction
  dlc/verify.rs    oracle, adaptor and refund signature verification
  btc.rs           Esplora inclusion lookup over enclave egress
  checks.rs        the structured report and what is allowed to block
  terms.rs         expected-term comparison and the terms digest
  event_id.rs      event-id matching, and the placeholder derivation
  decision.rs      assembles the verdict per profile
  handlers/dlc.rs  HTTP endpoints and the app proof
  fixtures.rs      sample contracts, generated from fixtures/
crates/e2e/        tests against a spawned server
frontend/          static demo page, deployed to GitHub Pages
fixtures/          Lygos sample contracts
tvc-configs/       app and deployment config, and the deploy script
```

`fixtures.rs` and `frontend/presets.js` are generated from `fixtures/*.json` rather than transcribed. An earlier attempt at this demo hand-copied a 1.8 KB hex string and silently transposed two bytes.
