# Lygos DLC verification in a TVC enclave

> ### Disclaimer
>
> **A demonstration, not a product.** Turnkey Solutions Engineering built it to show Lygos and their
> lending partner what verifying a DLC inside a TVC enclave looks like.
>
> **Unsupported and unaudited.** No SLA, no maintenance promise, no security contact. It can be
> redeployed or removed without notice. Running on Turnkey's production infrastructure does not make
> it production-ready, and nothing here is covered by any agreement you have with Turnkey.
>
> **Do not use it to gate real funds.** The gaps below are not theoretical. Several return a passing
> verdict where a production system has to refuse.
>
> Provided as is, without warranty of any kind, express or implied.

A Rust service that runs inside a [Turnkey Verifiable Cloud](https://docs.turnkey.com) enclave and
proves that a DLC contract is sound, and its collateral is
locked on Bitcoin.

It verifies the contract the way Lygos's own [`dlc-verify`](https://github.com/LygosLabs/dlc-verify)
does, covering message structure, the oracle's announcement signature, and every CET adaptor
signature. It then looks the collateral transaction up on Bitcoin over enclave egress and signs the
combined verdict with the enclave's ephemeral key.

## Known gaps

A non-comprehensive list of what a production system would need, not included in this demo.

1. **The attestation is not verified.** The service signs its verdict with the enclave's ephemeral
   key (an *app proof*) and the page checks that signature, but nothing pairs it with a *boot
   proof*, so nothing establishes that the signing key belongs to an enclave running this code. A
   passing signature check would look identical if it did not. See
   [How the lending partner verifies](#how-the-lending-partner-verifies-app-proofs-and-boot-proofs).
2. **Oracle event-id recomputation is a placeholder.** Lygos's derivation is not published and this
   demo does not guess at it, so the check reports `not_verifiable`, never a pass or a fail. The
   exact-match check against a caller-supplied event id is real. Substituting their derivation is a
   one-function change in `event_id.rs`.
3. **A passing `morpho_midnight` verdict does not prove the collateral belongs to the contract.**
   `funding_output_match` reports whether the transaction pays the contract's 2-of-2 script for the
   right amount, but it is *informational*, so a verdict can read `verified` while pointing at an
   unrelated transaction. A production gate has to make it blocking. It is informational here
   because the sample contracts were never broadcast, so no real transaction can satisfy it.
4. **One confirmation counts as settled.** `MIN_CONFIRMATIONS` is 1.
5. **This is a reimplementation of `dlc-verify`.** It agrees with DDK on these fixtures,
   byte-for-byte on the funding transaction, but it can drift as Lygos changes theirs.
6. **CORS is fully permissive** so the GitHub Pages page can call the enclave. Every endpoint is a
   read-only verification and the enclave holds no per-user state.
7. **The sample contracts were never broadcast.** The prefilled collateral transaction is a real but
   unrelated testnet3 transaction, present so the on-chain step runs against something, which is why
   `fundingOutputMatch` is `false` on the happy path. Clearing the field makes the app fall back to
   the contract's own derived `fundTxid`, which correctly reports `TX_NOT_FOUND`.

## Differences from node dlc-verify

| | [`dlc-verify`](https://github.com/LygosLabs/dlc-verify) | This repo |
| --- | --- | --- |
| Language | TypeScript on Node | Rust, statically linked against musl |
| Cryptographic core | [DDK](https://www.npmjs.com/package/@bennyblader/ddk-ts), a prebuilt native addon | [`rust-dlc`](https://github.com/p2pderivatives/rust-dlc) 0.8, plus the three pieces below |
| Wire decoding | node-dlc | `dlc/codec.rs`, because `rust-dlc` cannot read node-dlc offers |
| Runs inside a TVC enclave | No | Yes |
| Beyond contract verification | Nothing | Expected-term comparison, on-chain collateral lookup, structured check report, profiles, app proof |

A TVC deployment is a single binary whose SHA-256 is approved
before it can run, so a Node runtime plus an opaque `.node` file does not fit: the digest would
cover a launcher script rather than the code doing the verifying.

`rust-dlc` is not a drop-in replacement for DDK. Three things had to be worked out to make it
produce the same answers, and each has a test that fails loudly if it regresses.

**1. node-dlc writes a field `rust-dlc` does not read.** Lygos serializes with `node-dlc`, which
appends an optional `dlc_input` to every funding input so a DLC can be funded by another DLC's
output. `rust-dlc` 0.8 has no such field, and because it writes no per-element framing inside a
vector, the extra byte does not reliably fail. On a one-input offer the parse *succeeds* with
garbage: we measured a `fee_rate_per_vb` of 5,263,947,935,078,877,696 where the real value was 3,
and every downstream number including the adaptor signatures would follow from it. `dlc/codec.rs`
decodes offers itself, and a test asserts the upstream parser disagrees.

**2. `rust-dlc` validates oracle announcements with the wrong hash.** `OracleAnnouncement::validate`
uses a plain SHA-256 over the non-TLV encoding where the specification uses a BIP340 tagged hash
over the TLV encoding, so it reports valid announcements as invalid. `dlc/verify.rs` does the
tagged-hash check instead.

**3. Lygos loans are single-funded, which `rust-dlc` refuses to build.** The borrower supplies all
the collateral and all the inputs, and `create_dlc_transactions` charges each party for its own
fees. DDK handles it, which is why `dlc-verify` needs DDK at all. `dlc/txs.rs` reimplements that
construction, matching DDK byte for byte on three details:

- The borrower alone bears the **whole** fund-transaction base weight, not half.
- The CET fee is **prepaid into the fund output**, so it holds `total_collateral + cet_fee` and each
  CET pays the full unreduced payout.
- A CET carries one output per non-dust payout, so an all-or-nothing loan CET has exactly one.

This has to be exact, because an adaptor signature commits to the CET's sighash and one wrong byte
invalidates every signature. For the sample contract it produces a fund output of 11,470 sat (10,000
collateral plus 1,470 prepaid CET fee), a fund fee of 2,490 sat, and fund txid `15659a28…604274`,
which is what DDK produces and what the tests assert.

## Two use cases

The same verification serves two callers who need different things proven. `profile` on the request
decides what is allowed to block the verdict. The cryptography is identical either way.

**Institutional lender.** For a lending partner independently checking every loan they advance
against, without taking Lygos's word for any of it. Lygos hands them the offer, accept and sign
messages, and they supply the terms they agreed to: lender key, oracle key and event id, repayment
and liquidation destinations, refund address and locktime, maturity, collateral, payouts. The
enclave confirms the contract is cryptographically sound, that it encodes those terms, and that the
collateral is locked on Bitcoin, querying the chain itself rather than trusting a figure it was
handed.

A collateral transaction is optional but gates the verdict when present, since a lender may
legitimately review terms before the borrower has posted collateral. The report then says the
collateral was **not checked** rather than implying it passed. Once the chain is consulted,
unconfirmed collateral blocks. Being the lender does not make that check optional.

**Morpho Midnight.** The same verification, plus proof the collateral is funded. The enclave
reconstructs the expected funding transaction from the DLC itself, then queries Bitcoin over egress.
The output is the signed verdict the Midnight contracts consume before minting a collateral
representation, which lets the guardian network keep securing the lender key without also acting as
the verification quorum. The response carries a `termsDigest`, a hash over the expected terms, so
the EVM side can bind minting to exactly the terms that were verified.

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
| `not_verifiable` | No verdict is possible, as with the placeholder event-id derivation |

A `required` check only satisfies the verdict on `pass`. Treating `not_checked` as success is how a
gate ends up approving something it never verified, so an expectation you did not state can never be
mistaken for one that was met. Supplying no terms at all fails outright rather than reporting a
green built on nothing.

`failureReasons` gives a caller a small set to branch on: `MALFORMED_INPUT`,
`DLC_VERIFICATION_FAILED`, `MISMATCH_EXPECTED_VS_PARSED`, `TX_NOT_FOUND`, `EXPLORER_REQUEST_FAILED`,
`CHECK_NOT_VERIFIABLE`. `blockingChecks` names precisely which required checks did not pass. A
contract that is cryptographically perfect but encodes different terms fails as a mismatch rather
than as broken cryptography, because those are different problems.

The event id ties the DLC to a *specific* loan, so it is checked twice: exact match against an id
the caller expects, which is real, and recomputation from the loan parameters, which is the
placeholder in gap 2. The recomputation still earns its place, because every loan parameter affects
the derived id, so altering any term visibly changes it, which is the whole argument for the real
check.

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

`profile` is `institutional_lender` or `morpho_midnight` and is **never overridden**, so a report
always describes the use case that was asked for. Omitting it defaults to `institutional_lender` on
`/dlc/verify` and `morpho_midnight` on `/dlc/verify_loan`.

Everything under `expected` is optional, but a request with no expectations at all fails rather than
reporting a verdict it cannot support. Omit `btcTxid` and the app checks the fund transaction it
derived from the contract, which is the production behaviour.

The two endpoints differ only in whether the chain is consulted, not in how strict they are. Use
`/dlc/verify_loan` whenever a collateral transaction matters, including as a lender. `/dlc/verify`
performs no I/O, so it reports the collateral as `not_checked`, and for `morpho_midnight` that is a
blocking omission rather than an acceptable answer.

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

To check the signature, note that `publicKey` is two concatenated uncompressed P-256 points and the
**second** one is the signing key. The signature is raw `r||s`, and the signed message is `payload`
verbatim. `frontend/index.html` does this with WebCrypto in about fifteen lines.

### How the lending partner verifies: app proofs and boot proofs

This is the part Lygos's lending partner implements, and the shape worth taking away from the demo.
Turnkey's [model](https://docs.turnkey.com/security/turnkey-verified#app-proofs) is two proofs: an
**app proof**, the enclave's P-256 signature over the verdict, which is what this service returns,
and a **boot proof**, the AWS Nitro attestation document plus signed QOS manifest produced by the
platform at boot, which states the enclave's PCR measurements and carries the ephemeral public key
in its `public_key` field.

Neither is sufficient alone. The signature says the holder of a key produced this verdict. The boot
proof says which code holds that key.

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
[`proof.ts`](https://github.com/tkhq/sdk/tree/main/packages/crypto/src/proof.ts) in TypeScript. 

## Running locally

```sh
make lint
make test
make run      # 127.0.0.1:44020
```

Then open `frontend/index.html`. It points at `http://127.0.0.1:44020` by default. To aim it
elsewhere:

```sh
cd frontend && TVC_APP_URL=https://app-<APP_ID>.app.turnkey.cloud ./build.sh
```

`make run` generates throwaway keys in `/tmp/tvc-template-local-enclave`, so proofs verify against a
key that is *not* attested. Local runs check routing and verification logic. Only a deployed enclave
demonstrates the attestation, and even there the boot proof is not checked.

Never enable debug mode on a production app. It zeroes the attestation PCRs and permanently
marks the app's quorum key insecure, and neither can be undone by a later non-debug deployment. Use
it only on a development app.

## Deploying

The deploy config pins an image digest and the SHA-256 of the binary inside it. Only a reproducible
StageX build produces those, so every deployment goes through CI.

`tvc login` should be run first and configured to your org. `tvc-configs/` holds a config pair per
environment.

Org, app and operator identifiers are not committed. The configs carry placeholders, and the real
values go in `tvc-configs/local.env`, which is gitignored. See `tvc-configs/README.md`.

```sh
cargo install tvc --locked   # 0.14.0 or newer
cp tvc-configs/local.env.example tvc-configs/local.env   # then fill it in
tvc login                    # defaults to production, https://api.turnkey.com
ENV=prod ./tvc-configs/render-app-config.sh
tvc app create --config-file tvc-configs/app.local.json  # record the ids it prints
```

`enableEgress` and debug mode **cannot be added to an app later**, and `tvc-configs/app.json`
requires **tvc >= 0.14.0**. Older CLIs name those fields differently (`externalConnectivity`,
`debugMode`) and have no app-level debug field, so they silently produce an app that has working
egress but can never serve debug logs. Check with `cargo install --list | grep tvc` before creating
anything.

Then per pass: run `make lint test`, push, wait for the `stagex` workflow, and take **Container Image
URL** and **Expected Executable Digest** from its summary.

```sh
ENV=prod ./tvc-configs/deploy-latest.sh
```

The app URL is stable at `https://app-<APP_ID>.app.turnkey.cloud` on production and
`https://app-<APP_ID>.apps.tvc-dev.turnkey.engineering` on dev, so only the deployment changes.
Delete the superseded deployment once the new one serves traffic, otherwise it is ambiguous which
build answered a request.

**Notes:**

1. A newly created `ghcr.io/tkhq/dlc-verify` package is **private** and the enclave cannot pull it.
   Make it public or pass `--pivot-pull-secret`.
2. `expectedPivotDigest` is the digest of the binary *inside* the image, not the image digest.
   Confusing the two fails inside the enclave rather than at create time.
3. Always pin `@sha256:`. A bare `:pr-N` tag moves with every push, so the manifest you approve
   stops describing the code you meant to test.
4. Approval does not promote a deployment. The previous one keeps serving traffic until
   `tvc app set-live-deploy`, and `/health` returns 200 throughout, so this looks exactly like a
   successful deploy of code that is not running.
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
