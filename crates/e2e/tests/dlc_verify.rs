#![allow(missing_docs, clippy::unwrap_used, clippy::expect_used)]
//! End-to-end tests against a spawned server.
//!
//! These exercise the HTTP surface and the app proof. Tests that would require outbound
//! network access are deliberately absent: `/dlc/verify_loan` reaches the public
//! Blockstream API, which is not something a test suite should depend on. The chain
//! lookup is covered by unit tests in the `dlc-verify` crate and by curling the deployed
//! enclave.

use e2e::TestArgs;
use qos_p256::P256Public;
use serde_json::json;

/// The Lygos-provided sample contract, read from the fixture the frontend also uses.
fn sample_request() -> serde_json::Value {
    let fixture: serde_json::Value =
        serde_json::from_str(include_str!("../../../fixtures/sample-dlc-messages.json")).unwrap();
    json!({
        "offerHex": fixture["offerHex"],
        "acceptHex": fixture["acceptHex"],
        "signHex": fixture["signHex"],
        "network": "regtest",
    })
}

/// Terms that match the sample contract exactly, so a failure means a real regression
/// rather than a stale expectation.
fn matching_terms() -> serde_json::Value {
    json!({
        "lenderPubkey": "031d770999fe6a338c88ea93873bff6ad540cbd86a338fdffe11f662c8a05d7be2",
        "borrowerPubkey": "030fac9748b7cb45f66562a6a1f578ebdfe38b0938a87637590016726e470a7053",
        "oraclePubkey": "8731249d979def2d5d76c61795969e953807d37ff36ef8dbab60d57ae08bb004",
        "oracleEventId": "loan-matured-1da042f2fa3a59cacbe6bf8c1abc3d6b2abc66d4b3a48c2567aedce8d81563ef",
        "totalCollateralSats": 10000,
        "feeRatePerVb": 10,
        "repayment": { "address": "bcrt1q6tas5tud2w420rl5g45fa5knfepa4qmxuq3xff", "sats": 10000 },
        "liquidation": { "address": "bcrt1qup6w2fa79hfyfkar473zyvfewz7xz7vhtu3qsx" },
        "refund": { "address": "bcrt1q6tas5tud2w420rl5g45fa5knfepa4qmxuq3xff", "locktime": 1790352000u64 },
        "cetLocktime": 1781734876u64,
        "outcomes": [
            { "label": "repaid", "offererSats": 10000, "accepterSats": 0 },
            { "label": "liquidated-by-price-threshold", "offererSats": 0, "accepterSats": 10000 }
        ],
    })
}

/// The lender flow: contract plus terms, no chain lookup.
fn lender_request() -> serde_json::Value {
    let mut request = sample_request();
    request["profile"] = json!("institutional_lender");
    request["expected"] = matching_terms();
    request
}

#[tokio::test]
async fn health_reports_healthy() {
    async fn test(args: TestArgs) {
        let resp = reqwest::Client::new()
            .get(format!("{}/health", args.base_url))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let json: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(json["status"], "healthy");
    }
    e2e::Builder::new().execute(test).await;
}

#[tokio::test]
async fn verifies_the_sample_contract_and_signs_the_result() {
    async fn test(args: TestArgs) {
        let resp = reqwest::Client::new()
            .post(format!("{}/dlc/verify", args.base_url))
            .json(&lender_request())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let json: serde_json::Value = resp.json().await.unwrap();

        assert_eq!(json["status"], "verified", "unexpected verdict: {json}");
        assert_eq!(json["dlc"]["adaptorSigsValid"], true);
        assert_eq!(json["dlc"]["adaptorValidCount"], 5);
        assert_eq!(json["dlc"]["oracleSigValid"], true);
        assert_eq!(json["dlc"]["signContractIdMatches"], true);
        assert_eq!(json["dlc"]["singleFunded"], true);
        assert_eq!(json["dlc"]["accepterRefundSigValid"], true);
        assert_eq!(json["dlc"]["offererRefundSigValid"], true);
        assert_eq!(
            json["dlc"]["fundTxid"],
            "15659a28391a81337f7512427e0a07b3f32d16514f81f58303adec3955604274"
        );
        assert!(json["failureReasons"].as_array().unwrap().is_empty());

        // The proof must verify against the exact bytes the enclave returned.
        let payload = json["proof"]["payload"].as_str().unwrap();
        let public_key = P256Public::from_bytes(
            &qos_hex::decode(json["proof"]["publicKey"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let signature = qos_hex::decode(json["proof"]["signature"].as_str().unwrap()).unwrap();
        public_key
            .verify(payload.as_bytes(), &signature)
            .expect("the enclave's signature should verify over its own payload");

        // And the signed payload must be the decision itself, not a summary of it.
        let signed: serde_json::Value = serde_json::from_str(payload).unwrap();
        assert_eq!(signed["status"], "verified");
    }
    e2e::Builder::new().execute(test).await;
}

/// Verifying against no expectations must not report success. The cryptography is still
/// reported as valid — it genuinely is — but "this contract is well-formed" is a weaker
/// claim than "this contract matches our loan", and the verdict must reflect the weaker one.
#[tokio::test]
async fn a_contract_with_no_expected_terms_does_not_verify() {
    async fn test(args: TestArgs) {
        let json: serde_json::Value = reqwest::Client::new()
            .post(format!("{}/dlc/verify", args.base_url))
            .json(&sample_request())
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert_eq!(json["status"], "failed");
        assert_eq!(json["blockingChecks"], json!(["expected_terms_supplied"]));
        // The contract's own cryptography is sound and should be reported as such.
        assert_eq!(json["dlc"]["adaptorSigsValid"], true);
        assert_eq!(json["dlc"]["oracleSigValid"], true);
    }
    e2e::Builder::new().execute(test).await;
}

#[tokio::test]
async fn a_wrong_expected_oracle_key_fails_the_verification() {
    async fn test(args: TestArgs) {
        let mut request = lender_request();
        request["expected"]["oraclePubkey"] = json!("ff".repeat(32));

        let resp = reqwest::Client::new()
            .post(format!("{}/dlc/verify", args.base_url))
            .json(&request)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let json: serde_json::Value = resp.json().await.unwrap();

        assert_eq!(json["status"], "failed");
        assert_eq!(
            json["failureReasons"],
            json!(["MISMATCH_EXPECTED_VS_PARSED"]),
            "the contract is sound; only the caller's expectation was violated"
        );
        assert_eq!(json["blockingChecks"], json!(["oracle_pubkey"]));
        assert_eq!(json["dlc"]["adaptorSigsValid"], true);
    }
    e2e::Builder::new().execute(test).await;
}

#[tokio::test]
async fn malformed_messages_are_rejected_without_crashing_the_server() {
    async fn test(args: TestArgs) {
        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{}/dlc/verify", args.base_url))
            .json(&json!({"offerHex": "not-hex", "acceptHex": "also-not-hex"}))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let json: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(json["status"], "failed");
        assert_eq!(json["failureReasons"], json!(["MALFORMED_INPUT"]));

        // A missing required field is a client error, not a verdict.
        let resp = client
            .post(format!("{}/dlc/verify", args.base_url))
            .json(&json!({"offerHex": "00"}))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_client_error());

        // The server is still healthy afterwards.
        let resp = client
            .get(format!("{}/health", args.base_url))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }
    e2e::Builder::new().execute(test).await;
}

#[tokio::test]
async fn app_key_matches_the_key_that_signs_proofs() {
    async fn test(args: TestArgs) {
        let client = reqwest::Client::new();
        let key: serde_json::Value = client
            .get(format!("{}/app_key", args.base_url))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        let proof: serde_json::Value = client
            .post(format!("{}/dlc/verify", args.base_url))
            .json(&lender_request())
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert_eq!(key["publicKey"], proof["proof"]["publicKey"]);
        assert_eq!(key["algorithm"], "P256");
    }
    e2e::Builder::new().execute(test).await;
}

#[tokio::test]
async fn cors_headers_allow_the_github_pages_frontend() {
    async fn test(args: TestArgs) {
        let resp = reqwest::Client::new()
            .get(format!("{}/health", args.base_url))
            .header("origin", "https://tkhq.github.io")
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.headers()
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok()),
            Some("*")
        );
    }
    e2e::Builder::new().execute(test).await;
}

#[tokio::test]
async fn the_lender_flow_verifies_the_contract_against_agreed_terms() {
    async fn test(args: TestArgs) {
        let resp = reqwest::Client::new()
            .post(format!("{}/dlc/verify", args.base_url))
            .json(&lender_request())
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let json: serde_json::Value = resp.json().await.unwrap();

        assert_eq!(json["status"], "verified", "unexpected verdict: {json}");
        assert_eq!(json["profileLabel"], "Institutional lender");
        assert!(json["blockingChecks"].as_array().unwrap().is_empty());
        assert!(
            json["termsDigest"].as_str().is_some_and(|d| d.len() == 64),
            "a terms digest is what another system binds to"
        );

        // Every required check must have actually passed, not merely not-failed.
        for check in json["checks"].as_array().unwrap() {
            if check["severity"] == "required" {
                assert_eq!(
                    check["status"], "pass",
                    "required check {} did not pass",
                    check["id"]
                );
            }
        }

        // The lender flow must not depend on the chain.
        let funding = json["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == "onchain_funding")
            .unwrap();
        assert_eq!(funding["severity"], "informational");
    }
    e2e::Builder::new().execute(test).await;
}

#[tokio::test]
async fn a_single_wrong_term_fails_and_names_the_term() {
    async fn test(args: TestArgs) {
        let client = reqwest::Client::new();
        // Each of these is a sound contract for *different* terms, which is exactly the
        // case cryptographic validity alone cannot catch.
        for (field, value, expected_block) in [
            (
                "liquidation",
                json!({"address": "bcrt1qwrongwrongwrongwrongwrongwrongwrongwr"}),
                "liquidation_address",
            ),
            ("cetLocktime", json!(1781734999u64), "cet_locktime"),
            ("totalCollateralSats", json!(9999), "total_collateral"),
            ("oracleEventId", json!("loan-matured-00"), "oracle_event_id"),
        ] {
            let mut request = lender_request();
            request["expected"][field] = value;

            let json: serde_json::Value = client
                .post(format!("{}/dlc/verify", args.base_url))
                .json(&request)
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();

            assert_eq!(json["status"], "failed", "{field} should fail");
            assert_eq!(
                json["blockingChecks"],
                json!([expected_block]),
                "{field} should block on exactly {expected_block}"
            );
            // The contract itself is still sound; only the expectation was violated.
            assert_eq!(json["dlc"]["adaptorSigsValid"], true, "{field}");
        }
    }
    e2e::Builder::new().execute(test).await;
}

#[tokio::test]
async fn the_midnight_profile_requires_confirmed_collateral() {
    async fn test(args: TestArgs) {
        // Same contract and terms as the passing lender case, but under the cross-chain
        // profile and with no collateral transaction: funding must now gate.
        let mut request = lender_request();
        request["profile"] = json!("morpho_midnight");

        let json: serde_json::Value = reqwest::Client::new()
            .post(format!("{}/dlc/verify", args.base_url))
            .json(&request)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        assert_eq!(json["status"], "failed");
        assert!(
            json["blockingChecks"]
                .as_array()
                .unwrap()
                .contains(&json!("onchain_funding"))
        );
        assert!(
            !json["failureReasons"].as_array().unwrap().is_empty(),
            "a failure must always carry a reason to branch on"
        );
    }
    e2e::Builder::new().execute(test).await;
}

#[tokio::test]
async fn evm_terms_are_echoed_into_the_attestation_without_being_verified() {
    async fn test(args: TestArgs) {
        let mut request = lender_request();
        request["profile"] = json!("morpho_midnight");
        request["expected"]["evm"] = json!({"position": "morpho-1", "collateralSats": 10000});

        let json: serde_json::Value = reqwest::Client::new()
            .post(format!("{}/dlc/verify", args.base_url))
            .json(&request)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        let echoed = json["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == "evm_terms_echoed")
            .expect("evm terms should appear in the report");
        assert_eq!(echoed["severity"], "informational");
        assert_eq!(
            echoed["status"], "not_verifiable",
            "echoed terms must never read as verified"
        );
        // And they must be inside the signed payload, so the EVM side can bind to them.
        let payload = json["proof"]["payload"].as_str().unwrap();
        assert!(payload.contains("morpho-1"));
    }
    e2e::Builder::new().execute(test).await;
}

#[tokio::test]
async fn the_placeholder_event_id_derivation_reports_no_verdict() {
    async fn test(args: TestArgs) {
        let mut request = lender_request();
        request["expected"]["loanTerms"] = json!({
            "loanId": "LYG-1", "principal": "50000", "repaymentAmount": "52500",
            "maturityTimestamp": 1781734876u64, "collateralSats": 10000,
            "liquidationPrice": "45000"
        });

        let json: serde_json::Value = reqwest::Client::new()
            .post(format!("{}/dlc/verify", args.base_url))
            .json(&request)
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

        let check = json["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == "oracle_event_id_recomputed")
            .unwrap();
        assert_eq!(check["status"], "not_verifiable");
        assert!(
            check["detail"]
                .as_str()
                .unwrap()
                .contains("DEMO_PLACEHOLDER"),
            "the report must say the derivation is not Lygos's rule"
        );
        // It must not block, since we cannot fault the contract for our missing rule.
        assert_eq!(json["status"], "verified");
    }
    e2e::Builder::new().execute(test).await;
}
