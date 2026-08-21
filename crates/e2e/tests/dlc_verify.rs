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
    })
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
            .json(&sample_request())
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

#[tokio::test]
async fn a_wrong_expected_oracle_key_fails_the_verification() {
    async fn test(args: TestArgs) {
        let mut request = sample_request();
        request["expectedOraclePubkey"] = json!("ff".repeat(32));

        let resp = reqwest::Client::new()
            .post(format!("{}/dlc/verify", args.base_url))
            .json(&request)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
        let json: serde_json::Value = resp.json().await.unwrap();

        assert_eq!(json["status"], "failed");
        assert_eq!(json["dlc"]["oraclePubkeyMatchesExpected"], false);
        assert_eq!(
            json["failureReasons"],
            json!(["MISMATCH_EXPECTED_VS_PARSED"]),
            "the contract is sound; only the caller's expectation was violated"
        );
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
            .json(&sample_request())
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
