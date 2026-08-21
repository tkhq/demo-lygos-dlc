//! Check that a deployed enclave is running the code its operator approved.
//!
//! This runs on the *client* side, which is the whole point. The enclave serves an
//! attestation document; deciding whether to believe it is the client's job, because an
//! enclave that graded its own attestation would simply report success.
//!
//! # What a full check establishes
//!
//! 1. The attestation document is signed by AWS Nitro, chaining to the hardcoded AWS root
//!    certificate. So it came from real Nitro hardware, not from something imitating it.
//! 2. The document's PCR measurements match an **approved manifest supplied locally**. So
//!    the enclave is running that exact code, rather than merely being a genuine enclave.
//! 3. The document commits to that manifest, so the enclave booted under it.
//! 4. The key bound into the document is the key the app signs verdicts with. So a signed
//!    verdict came from the attested enclave, rather than from anything else holding a key.
//! 5. The document echoes a nonce chosen here, so it is fresh rather than a replay.
//!
//! # Why `--manifest` matters
//!
//! Without it, the only PCRs available are the ones the enclave itself reports. Checking a
//! document against the server's own claim about what it should be proves that *some*
//! genuine enclave is running *something* — it cannot tell you which code. That is a real
//! but much weaker statement, so this tool draws the distinction loudly instead of letting a
//! green result imply more than it showed.

use clap::Parser;
use qos_core::protocol::QosHash;
use qos_core::protocol::services::boot::ManifestEnvelope;
use qos_nsm::nitro::{
    AWS_ROOT_CERT_PEM, ManifestAttestationInput, attestation_doc_from_der, cert_from_pem,
    verify_attestation_doc_against_manifest_live,
};
use serde::Deserialize;
use std::time::{SystemTime, UNIX_EPOCH};

/// Check a deployed TVC enclave's attestation.
#[derive(Parser, Debug)]
#[command(
    name = "attest-verify",
    about = "Verify that a TVC enclave is running approved code"
)]
struct Cli {
    /// Base URL of the deployed app.
    #[arg(long)]
    app_url: String,

    /// Path to the approved manifest, as JSON or as the raw envelope bytes.
    ///
    /// Without this the PCRs can only be compared against what the enclave itself reports,
    /// which does not establish which code is running.
    #[arg(long)]
    manifest: Option<String>,
}

/// The enclave's `/attestation` response.
///
/// Note what is deliberately absent: the response also carries `boundPublicKey` and `nonce`,
/// but those are unsigned JSON written by the server. The authenticated copies live inside
/// the attestation document, and that is where this tool reads them from. Comparing the
/// server's JSON against the server's JSON would prove nothing.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AttestationMaterial {
    available: bool,
    unavailable_reason: Option<String>,
    attestation_document: Option<String>,
    self_reported_manifest: Option<String>,
}

/// The enclave's `/app_key` response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AppKey {
    public_key: String,
}

/// Outcome of one check, for a report that distinguishes "proved" from "did not check".
enum Outcome {
    Pass(String),
    Fail(String),
    Skip(String),
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let base = cli.app_url.trim_end_matches('/').to_string();

    // A nonce chosen here, so the document cannot be one captured earlier. Derived from the
    // clock rather than a CSPRNG because it only needs to be unpredictable to a replayer.
    let nonce_bytes = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_nanos()
        .to_be_bytes();
    let nonce_hex = qos_hex::encode(&nonce_bytes);

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()?;

    let material: AttestationMaterial = client
        .get(format!("{base}/attestation?nonce={nonce_hex}"))
        .send()?
        .json()?;
    let app_key: AppKey = client.get(format!("{base}/app_key")).send()?.json()?;

    let mut outcomes = Vec::new();

    if !material.available {
        let reason = material
            .unavailable_reason
            .unwrap_or_else(|| "no reason given".to_string());
        println!("ATTESTATION UNAVAILABLE\n  {reason}");
        println!(
            "\nThe enclave returned no attestation document, so nothing about which code is \
             running can be established. If this is a local run, that is expected."
        );
        return Ok(());
    }

    let document_hex = material
        .attestation_document
        .ok_or("the enclave reported an available attestation but sent no document")?;
    let document = qos_hex::decode(&document_hex)
        .map_err(|e| format!("the attestation document was not hex: {e:?}"))?;

    // 1. The document is genuinely from Nitro hardware.
    let root_cert = cert_from_pem(AWS_ROOT_CERT_PEM)?;
    let now_secs = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let doc = match attestation_doc_from_der(&document, &root_cert, now_secs) {
        Ok(doc) => {
            outcomes.push(Outcome::Pass(
                "attestation document is signed by AWS Nitro and chains to the AWS root CA"
                    .to_string(),
            ));
            doc
        }
        Err(e) => {
            outcomes.push(Outcome::Fail(format!(
                "attestation document did not verify against the AWS Nitro root CA: {e:?}"
            )));
            report(&outcomes);
            std::process::exit(1);
        }
    };

    // 2. Freshness: the document must echo the nonce we just chose.
    match doc.nonce.as_ref().map(|n| qos_hex::encode(n.as_slice())) {
        Some(echoed) if echoed == nonce_hex => outcomes.push(Outcome::Pass(
            "document echoes the nonce chosen by this run, so it is not a replay".to_string(),
        )),
        Some(echoed) => outcomes.push(Outcome::Fail(format!(
            "document echoed nonce {echoed}, expected {nonce_hex}"
        ))),
        None => outcomes.push(Outcome::Fail(
            "document carries no nonce, so freshness cannot be established".to_string(),
        )),
    }

    // 3. The bound key is the key that signs verdicts.
    let bound = doc
        .public_key
        .as_ref()
        .map(|k| qos_hex::encode(k.as_slice()));
    match bound.as_deref() {
        Some(bound) if bound == app_key.public_key => outcomes.push(Outcome::Pass(
            "the key bound into the document is the key the app signs verdicts with".to_string(),
        )),
        Some(bound) => outcomes.push(Outcome::Fail(format!(
            "document binds key {bound}, but /app_key reports {}. A verdict signed by that \
             key is not covered by this attestation.",
            app_key.public_key
        ))),
        None => outcomes.push(Outcome::Fail(
            "document binds no public key, so no signed verdict can be tied to this enclave"
                .to_string(),
        )),
    }

    // 4. PCRs against an approved manifest. This is the check that identifies the code, and
    //    it is only meaningful if the manifest came from the operator rather than the server.
    match load_manifest(cli.manifest.as_deref()) {
        ManifestSource::Approved(envelope) => {
            // Informational: does the enclave's own copy agree with the approved one? The
            // verdict below rests only on the approved manifest, so this is not what makes
            // the check sound — but a mismatch means the enclave booted under something
            // other than what was handed to this tool, which is worth saying out loud.
            if let Some(reported) = material.self_reported_manifest.as_deref() {
                let approved = borsh::to_vec(&*envelope).map(|b| qos_hex::encode(&b));
                match approved {
                    Ok(approved) if approved == reported => outcomes.push(Outcome::Pass(
                        "the enclave's self-reported manifest is byte-identical to the \
                         approved one"
                            .to_string(),
                    )),
                    Ok(_) => outcomes.push(Outcome::Fail(
                        "the enclave reports booting under a different manifest than the \
                         approved one supplied here"
                            .to_string(),
                    )),
                    Err(e) => outcomes.push(Outcome::Skip(format!(
                        "could not re-encode the approved manifest to compare it: {e}"
                    ))),
                }
            }

            let config = &envelope.manifest.enclave;
            let manifest_hash = envelope.manifest.qos_hash();
            let expected = ManifestAttestationInput {
                manifest_hash: &manifest_hash,
                pcr0: &config.pcr0,
                pcr1: &config.pcr1,
                pcr2: &config.pcr2,
                pcr3: &config.pcr3,
            };
            match verify_attestation_doc_against_manifest_live(&doc, expected) {
                Ok(()) => outcomes.push(Outcome::Pass(
                    "PCRs match the approved manifest, and the document commits to it: this \
                     enclave is running the approved code"
                        .to_string(),
                )),
                Err(e) => outcomes.push(Outcome::Fail(format!(
                    "the running enclave does not match the approved manifest: {e:?}"
                ))),
            }
        }
        ManifestSource::SelfReported => outcomes.push(Outcome::Skip(
            "no --manifest supplied, so the PCRs were not checked against anything the \
             operator approved. A genuine Nitro enclave is running, but which code it runs \
             was NOT established."
                .to_string(),
        )),
        ManifestSource::Unreadable(e) => outcomes.push(Outcome::Fail(format!(
            "could not read the supplied manifest: {e}"
        ))),
    }

    report(&outcomes);
    if outcomes.iter().any(|o| matches!(o, Outcome::Fail(_))) {
        std::process::exit(1);
    }
    Ok(())
}

/// Where the expected values came from, which determines what a pass means.
enum ManifestSource {
    /// Supplied locally by whoever approved the deployment.
    Approved(Box<ManifestEnvelope>),
    /// Only the enclave's own claim is available, which cannot identify the code.
    SelfReported,
    /// A manifest was supplied but could not be read.
    Unreadable(String),
}

/// Load an operator-supplied manifest. The enclave's own copy is never used as the
/// expectation: see the module documentation.
fn load_manifest(path: Option<&str>) -> ManifestSource {
    let Some(path) = path else {
        return ManifestSource::SelfReported;
    };
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => return ManifestSource::Unreadable(format!("{path}: {e}")),
    };

    // Accept the raw envelope bytes, a hex dump of them, or JSON — all three are things a
    // person plausibly has on hand, and guessing wrong is a confusing failure.
    let candidate = match qos_hex::decode(String::from_utf8_lossy(&bytes).trim()) {
        Ok(decoded) => decoded,
        Err(_) => bytes,
    };
    if let Ok(envelope) = ManifestEnvelope::try_from_slice_compat(&candidate) {
        return ManifestSource::Approved(Box::new(envelope));
    }
    match serde_json::from_slice::<ManifestEnvelope>(&candidate) {
        Ok(envelope) => ManifestSource::Approved(Box::new(envelope)),
        Err(e) => ManifestSource::Unreadable(format!(
            "{path} is not a manifest envelope, as borsh or as JSON: {e}"
        )),
    }
}

/// Print the outcomes, making the difference between proved and unchecked obvious.
fn report(outcomes: &[Outcome]) {
    println!();
    for outcome in outcomes {
        match outcome {
            Outcome::Pass(m) => println!("  [PASS] {m}"),
            Outcome::Fail(m) => println!("  [FAIL] {m}"),
            Outcome::Skip(m) => println!("  [NOT CHECKED] {m}"),
        }
    }
    println!();

    let failed = outcomes.iter().any(|o| matches!(o, Outcome::Fail(_)));
    let skipped = outcomes.iter().any(|o| matches!(o, Outcome::Skip(_)));
    if failed {
        println!("RESULT: FAILED — do not trust verdicts from this enclave.");
    } else if skipped {
        println!(
            "RESULT: PARTIAL — the enclave is genuine Nitro hardware and its signing key is \
             attested, but which code it runs was not established. Re-run with --manifest \
             pointing at the approved manifest for a complete check."
        );
    } else {
        println!(
            "RESULT: VERIFIED — this enclave runs the approved code, and the key that signs \
             its verdicts is bound to that attestation."
        );
    }
}
