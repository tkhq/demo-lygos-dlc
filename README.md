# Lygos DLC verification in a TVC enclave

> ### Read this first
>
> **This is a demonstration.** Turnkey Solutions Engineering built it to show Lygos and their
> lending partner what verifying a DLC inside a TVC enclave looks like, and how a client would
> verify the result. It is illustrative code, not a product.
>
> **It is unsupported.** No SLA, no uptime commitment, no maintenance promise, no security
> contact. The deployment sits on Turnkey's **dev** environment and can be deleted or redeployed
> without notice. Nothing here is covered by any agreement you have with Turnkey.
>
> **It has not been audited or reviewed for security** by Turnkey or anyone else.
>
> **Do not use it to gate real funds, and do not treat its output as a source of truth about a
> real loan.** The gaps listed below are not theoretical. Several of them return a passing verdict
> in situations where a production system has to refuse.
>
> Provided as is, without warranty of any kind, express or implied.

A Rust service that runs inside a [Turnkey Verifiable Cloud](https://docs.turnkey.com) enclave and
answers one question about a Lygos loan: **is this contract sound, and is its collateral actually
locked on Bitcoin?**

It verifies the contract the way Lygos's own [`dlc-verify`](https://github.com/LygosLabs/dlc-verify)
does, covering message structure, the oracle's announcement signature, and every CET adaptor
signature. It then looks the collateral transaction up on Bitcoin over enclave egress and signs the
combined verdict with the enclave's ephemeral key.

## Known gaps

Everything here is something a production system would need and this demo does not do. Listed so
nobody discovers them during a call.

**The attestation is not verified.** The service signs its verdict with the enclave's ephemeral key
(an *app proof*), and the page checks that signature. Nothing pairs it with a *boot proof*, so
nothing establishes that the signing key belongs to an enclave running this code. A passing
signature check would look identical if it did not. See
[How the lending partner verifies](#how-the-lending-partner-verifies-app-proofs-and-boot-proofs).

**The quorum key is a shared bootstrap key.** `tvc deploy provisioning-details` reports *"uses the
insecure bootstrap quorum key"*. Every app created from `tvc app init` in this org carries the same
pre-filled `quorumPublicKey`, and no per-app key was provisioned through the share-set flow. This
service does not sign with the quorum key, but nothing depending on that key is secure here.

**Oracle event-id recomputation is a placeholder.** Lygos's derivation is not published, and this
demo does not guess at it. The check reports `not_verifiable`, never a pass or a fail. The
exact-match check against a caller-supplied event id is real.

**A passing `morpho_midnight` verdict does not prove the collateral belongs to the contract.** The
transaction is checked for inclusion and confirmations, and `funding_output_match` reports whether
it actually pays the contract's 2-of-2 script for the right amount. That check is *informational*,
so a verdict can read `verified` while pointing at an unrelated transaction. A production gate has
to make it blocking. It is informational here because the sample contracts were never broadcast, so
no real transaction can satisfy it.

**One confirmation counts as settled.** `MIN_CONFIRMATIONS` is 1. That is a demo value, not a
lending policy.

**This is a reimplementation of Lygos's `dlc-verify`, not that code running.** It agrees with DDK on
the fixtures here, byte-for-byte on the funding transaction, but it is a port and can drift as Lygos
changes theirs. No guarantee of equivalence.

**CORS is fully permissive** so the GitHub Pages page can call the enclave. Every endpoint is a
read-only verification and the enclave holds no per-user state, but do not copy this posture.

**The sample contracts are regtest and testnet fixtures that were never broadcast.** The prefilled
collateral transaction is a real but unrelated testnet transaction, present so the on-chain step
runs against something. It is not this contract's collateral.

## Why this is a rewrite rather than a port

`dlc-verify` is Node, and its cryptographic core is
[DDK](https://www.npmjs.com/package/@bennyblader/ddk-ts), a prebuilt native addon. TVC deployments
are a single statically linked binary whose SHA-256 is reviewed and approved before it can run. A
Node runtime plus an opaque `.node` binary does not fit that model: the digest would cover a
launcher script rather than the code doing the verifying, which is the entire point of the
attestation.

So the verification is reimplemented in Rust on
[`rust-dlc`](https://github.com/p2pderivatives/rust-dlc). Three things had to be worked out to make
that produce the same answers as DDK. Each one is load-bearing, and each has a test that fails
loudly if it regresses.

### 1. node-dlc writes a field `rust-dlc` does not read

Lygos serializes with `node-dlc`, which appends an optional `dlc_input` to every funding input
(`0x00` absent, `0x01` present, then two pubkeys and a contract id) so a DLC can be funded by
another DLC's output. `rust-dlc` 0.8's `FundingInput` has no such field.

The dangerous part is that this does not reliably fail. `rust-dlc` writes no per-element framing
inside a vector, so on a one-input offer the extra byte shifts everything after it and the parse
*succeeds* with garbage. We measured a `fee_rate_per_vb` of 5,263,947,935,078,877,696 where the real
value was 3. Every downstream number, including the fund transaction and therefore the adaptor
signatures, would be computed from that. `dlc/codec.rs` decodes offers itself, and a test asserts
the upstream parser disagrees, so nobody is tempted to "simplify" it back.

### 2. `rust-dlc` validates oracle announcements with the wrong hash

`OracleAnnouncement::validate` hashes the oracle event with a plain SHA-256 over its non-TLV
encoding. The DLC specification, and every announcement Lygos produces, uses a BIP340 tagged hash
over the TLV encoding. The upstream check reports valid announcements as invalid. `dlc/verify.rs`
does the tagged-hash check instead.

### 3. Lygos loans are single-funded, which `rust-dlc` refuses to build

The borrower supplies all the collateral and all the inputs. The lender supplies neither.
`rust-dlc`'s `create_dlc_transactions` rejects this because it charges each party for its own fees
and the lender has no inputs to charge. DDK handles it, which is why `dlc-verify` needs DDK at all.

`dlc/txs.rs` reimplements that construction. Three details differ from a symmetric DLC, all derived
by matching DDK's output byte for byte:

1. The borrower alone bears the **whole** fund-transaction base weight, not half.
2. The CET fee is **prepaid into the fund output**, so it holds `total_collateral + cet_fee` and
   each CET pays the full unreduced payout.
3. A CET carries one output per non-dust payout, so an all-or-nothing loan CET has exactly one.

This has to be exact. An adaptor signature commits to the CET's sighash, so one wrong byte
invalidates every signature. For the sample contract that means a fund output of 11,470 sat (10,000
collateral plus 1,470 prepaid CET fee), a fund fee of 2,490 sat, and fund txid `15659a28…604274`,
which is what DDK produces and what the tests assert.

## Two use cases

The same verification serves two callers who need different things proven. `profile` on the request
decides what is allowed to block the verdict. The cryptography is identical either way.

### Institutional lender

For a lending partner independently checking every loan they advance against, without taking
Lygos's word for any of it.

Lygos hands them the offer, accept and sign messages. They supply the terms they agreed to: lender
key, oracle key and event id, repayment and liquidation destinations, refund address and locktime,
maturity, collateral, payouts. The enclave confirms the contract is cryptographically sound, that it
encodes those terms, and that the borrower's collateral is locked on Bitcoin. It queries the chain
from inside the enclave rather than trusting a figure it was handed.

Supplying a collateral transaction is optional but gates the verdict when present. A lender may
legitimately review terms before the borrower has posted collateral, and the report then says the
collateral was **not checked** rather than implying it passed. Once the chain is consulted,
unconfirmed collateral blocks. Being the lender does not make that check optional.

### Morpho Midnight

The same verification, plus proof that the Bitcoin collateral is actually funded. The enclave
reconstructs the expected funding transaction from the DLC itself, then queries Bitcoin over egress
to confirm it is on chain with enough confirmations.

The output is the signed verdict the Midnight contracts consume before minting a collateral
representation, which lets the guardian network keep securing the lender key without also acting as
the verification quorum. Turning that signature into a full attestation needs a boot proof, covered
below.

The response carries a `termsDigest`, a hash over the expected terms, so the EVM side can bind
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

| Status | Meaning |
| --- | --- |
| `pass` | Checked and matched |
| `fail` | Checked and did not match |
| `not_checked` | The caller supplied no expectation, so nothing was compared |
| `not_verifiable` | No verdict is possible. See the event-id note below |

A `required` check only satisfies the verdict on `pass`. Treating `not_checked` as success is how a
gate ends up approving something it never verified, so an expectation you did not state can never be
mistaken for one that was met. Supplying no terms at all fails outright rather than reporting a
green built on nothing.

`failureReasons` gives a caller a small set to branch on: `MALFORMED_INPUT`,
`DLC_VERIFICATION_FAILED`, `MISMATCH_EXPECTED_VS_PARSED`, `TX_NOT_FOUND`,
`EXPLORER_REQUEST_FAILED`, `CHECK_NOT_VERIFIABLE`. `blockingChecks` names precisely which required
checks did not pass. A contract that is cryptographically perfect but encodes different terms fails
as a mismatch rather than as broken cryptography, because those are different problems.

### The oracle event id, and what is a placeholder

The event id ties the DLC to a *specific* loan, so it is worth checking two ways:

1. **Exact match** against an id the caller expects. This is real and works today.
2. **Recomputation** from the loan parameters, which proves the DLC encodes the terms the lender
   believes it does without trusting any id handed to them.

**The recomputation here uses a documented placeholder, not Lygos's derivation.** Their event ids
are `loan-matured-` plus a 32-byte hash, and that hash is not derived from anything inside the DLC.
It is computed over off-chain loan parameters whose encoding is not published, and three sample
contracts are not enough to recover it.

Rather than guess, `event_id.rs` reports `not_verifiable` and never a pass or a fail, so it cannot
produce a misleading green or blame the contract for our missing rule. It still earns its place:
every loan parameter affects the derived id, so altering any term visibly changes it, which is the
whole argument for the real check. Substituting Lygos's derivation is a one-function change.

### EVM terms are attested, not verified

`expected.evm` is echoed into the report and the signed payload as `informational`, labelled
`not verified here`. This service verifies the Bitcoin and DLC side, and the EVM side binds to the
same values through the `termsDigest`. Reporting them as checked would be a claim we cannot support.

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

`profile` is `institutional_lender` or `morpho_midnight`, and is **never overridden**. A report
always describes the use case that was asked for. Omitting it defaults to `institutional_lender` on
`/dlc/verify` and `morpho_midnight` on `/dlc/verify_loan`.

Everything under `expected` is optional, but a request with no expectations at all fails rather than
reporting a verdict it cannot support.

The two endpoints differ only in whether the chain is consulted, not in how strict they are. Use
`/dlc/verify_loan` whenever a collateral transaction matters, including as a lender, since
confirming the borrower's collateral is locked is the point of advancing against it. `/dlc/verify`
performs no I/O, so it can only answer the term-and-cryptography half. It reports the collateral as
`not_checked`, and for `morpho_midnight` that is a blocking omission rather than an acceptable
answer.

Omit `btcTxid` and the app checks the fund transaction it derived from the contract, which is the
production behaviour. Omit `expectedOraclePubkey` and the oracle-identity check is skipped rather
than assumed.

Every response carries a `proof`, the enclave's signature over the exact JSON of the verdict.

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

This is an **app proof** in the sense Turnkey's
[Verified](https://docs.turnkey.com/security/turnkey-verified#app-proofs) documentation uses the
term: a P-256 signature by the enclave's ephemeral key over a JSON payload.

To check the signature, note that `publicKey` is two concatenated uncompressed P-256 points and the
**second** one is the signing key. The signature is raw `r||s`, and the signed message is `payload`
verbatim. `frontend/index.html` does this with WebCrypto in about fifteen lines.

### How the lending partner verifies: app proofs and boot proofs

This is the part Lygos's institutional lending partner implements, and the shape worth taking away
from the demo. Turnkey's model is two proofs:

1. An **app proof**, the enclave's P-256 signature over the verdict, which is what this service
   returns.
2. A **boot proof**, the AWS Nitro attestation document plus the signed QOS manifest, produced by
   the platform at boot. It states the enclave's PCR measurements and carries the ephemeral public
   key in its `public_key` field.

Neither is sufficient alone. The signature says the holder of a key produced this verdict. The boot
proof says which code holds that key. The partner's check:

| Step | What it establishes | In this demo |
| --- | --- | --- |
| 1. Verify the app proof signature over the verdict | The verdict came from the holder of this key and was not altered | **Runs for real, in the browser** |
| 2. Fetch the boot proof for the enclave | The measurements and the key the platform attested to | Shown, not performed |
| 3. Confirm `bootProof.public_key` equals the app proof's `publicKey` | **The join.** Ties this verdict to a specific attested enclave | Shown, not performed |
| 4. Check PCRs and the application digest against independently held values | The enclave runs the code you approved | Shown, not performed |

Step 4 only means something if the expected values come from somewhere other than the server that
supplied the document. Comparing a boot proof against PCRs the same host also provided shows that
*some* genuine enclave is running *something*, which is a much weaker statement than it looks.

Use Turnkey's verifiers rather than writing your own:
[`turnkey_proofs`](https://github.com/tkhq/rust-sdk/tree/main/proofs) in Rust, and
[`proof.ts`](https://github.com/tkhq/sdk/tree/main/packages/crypto/src/proof.ts) in TypeScript. The
TypeScript one means in-browser boot-proof verification is largely solved rather than a COSE
reimplementation.

**One open question to resolve with Turnkey.** For a *TVC app* it is not obvious how a client
retrieves the boot proof. Neither `tvc` nor the `turnkey` CLI exposes a command for it, and the
deployed app serves no such endpoint. The documented flow covers Turnkey's own enclaves. The partner
needs a supported way to fetch it, so this is worth settling before they build step 2.

**Do not have the app mint its own attestation document.** An earlier version of this repo added an
`/attestation` endpoint calling the Nitro Secure Module directly. That is the wrong mechanism. The
boot proof already exists and already binds the ephemeral key, and an enclave vouching for itself
proves nothing regardless. It was reverted.

## Running locally

```sh
make lint
make test
make run      # 127.0.0.1:44020
```

Then open `frontend/index.html`. It points at `http://127.0.0.1:44020` by default. To aim it
elsewhere:

```sh
cd frontend && TVC_APP_URL=https://app-<APP_ID>.apps.tvc-dev.turnkey.engineering ./build.sh
```

`make run` generates throwaway keys in `/tmp/tvc-template-local-enclave`, so proofs verify against a
key that is *not* attested. Local runs check routing and verification logic. Only a deployed enclave
demonstrates the attestation.

> **What the proof shows.** The signature proves the holder of the published key produced these
> exact bytes. Tying that key to attested code needs a boot proof, which this demo does not do. The
> deployed app has debug mode off, so the PCRs behind such a proof would be real, but nothing here
> checks them.
>
> Debug mode makes this strictly worse. It zeroes the PCRs outright and permanently marks the app's
> quorum key insecure, which cannot be undone by a later non-debug deployment. Use it only while
> iterating, on an app you intend to throw away.

### About the demo transaction id

The sample contracts are regtest and testnet fixtures that were never broadcast, so their own fund
transactions cannot be looked up on a public explorer. The frontend prefills a real confirmed
testnet3 transaction so the on-chain step genuinely runs.

That transaction has nothing to do with the sample contract, so `fundingOutputMatch` is `false`,
reported for information and not counted as a failure. Clearing the field makes the app fall back to
the contract's own derived `fundTxid`, which correctly reports `TX_NOT_FOUND` for a contract that
was never broadcast.

## Deploying

The deploy config pins an image digest and the SHA-256 of the binary inside it. Only a reproducible
StageX build produces those, so every deployment goes through CI.

One-time setup. Note that `enableEgress` and debug mode **cannot be added to an app later**:

```sh
cargo install tvc --locked   # 0.14.0 or newer, see below
tvc login --api-base-url https://api.dev.turnkey.engineering
tvc app create --config-file tvc-configs/app.json   # record the app id and operator id
```

`tvc-configs/app.json` targets **tvc >= 0.14.0**. An older CLI names these fields differently
(`externalConnectivity` for egress, `debugMode` on the deployment) and has no app-level debug field
at all. Creating the app with one silently produces an app that egress works on but that can never
serve debug logs, and neither flag can be changed afterwards. Check with
`cargo install --list | grep tvc` before creating anything.

Then per pass: run `make lint test`, push, wait for the `stagex` workflow, take **Container Image
URL** and **Expected Executable Digest** from its summary, and deploy them.

```sh
OPERATOR_ID=<operator-id> ./tvc-configs/deploy-latest.sh
```

The app URL is stable at `https://app-<APP_ID>.apps.tvc-dev.turnkey.engineering`, so only the
deployment changes. Delete the superseded deployment once the new one serves traffic, otherwise it
is ambiguous which build answered a request.

Worth knowing:

1. A newly created `ghcr.io/tkhq/dlc-verify` package is **private** and the enclave cannot pull it.
   Make it public or pass `--pivot-pull-secret`.
2. `expectedPivotDigest` is the digest of the binary *inside* the image, not the image digest.
   Confusing the two produces a deployment that fails inside the enclave rather than at create time.
3. Always pin `@sha256:`. A bare `:pr-N` tag moves with every push, so the manifest you approve
   stops describing the code you meant to test.
4. Debug logs (`tvc deploy debug-logs --poll`) need debug mode on both the app and the deployment.
5. A cold StageX cache can run close to the 60-minute timeout. A slow build is not a hung build.

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

`fixtures.rs` and `frontend/presets.js` are generated from `fixtures/*.json` rather than
transcribed. An earlier attempt at this demo hand-copied a 1.8 KB hex string and silently transposed
two bytes.
