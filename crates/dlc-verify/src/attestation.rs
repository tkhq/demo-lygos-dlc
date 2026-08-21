//! Serving the material a client needs to check that this enclave is what it claims to be.
//!
//! Signing a verdict with a key only proves that whoever holds the key signed it. On its own
//! that says nothing about *what code* holds the key, which is the entire claim of running in
//! an enclave. Closing that gap needs an AWS Nitro attestation document: a structure signed
//! by the Nitro hypervisor that states the PCR measurements of the running enclave and can
//! carry a public key chosen by the enclave.
//!
//! So this module asks the Nitro Secure Module for a document with **this app's signing key
//! bound into it**. A client that verifies the document then knows the key which signed a
//! verdict lives inside an enclave whose measurements it can check.
//!
//! # This module deliberately does not verify anything
//!
//! An enclave grading its own attestation is worthless — a compromised one would simply
//! report success. Verification belongs to the client, which is why the `attest-verify`
//! crate exists and why everything here is raw material rather than a verdict.
//!
//! The same reasoning applies to the *expected* PCR values. They are published in the
//! manifest, and this endpoint serves the manifest the enclave booted with — but a client
//! must not take the expectation and the evidence from the same untrusted place. Comparing a
//! document against PCRs the server also supplied proves only that *some* genuine enclave is
//! running *something*. To learn which code is running, the expected manifest has to come
//! from whoever approved the deployment. `attest-verify` enforces that distinction and says
//! loudly when it is only echoing the server's own claim.
//!
//! # Off the enclave
//!
//! There is no NSM device outside a Nitro enclave, so the request fails. That is reported as
//! unavailable rather than as an error, so `make run` locally still works and the failure
//! mode is legible instead of looking like a crash.

use qos_nsm::types::{NsmRequest, NsmResponse};
use qos_nsm::{Nsm, NsmProvider};
use serde::Serialize;

/// Everything a client needs to check this enclave, and nothing resembling a verdict.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttestationMaterial {
    /// Whether an attestation document could be obtained at all.
    pub available: bool,
    /// Why it could not, when it could not. Populated only when `available` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
    /// The COSE_Sign1 attestation document, hex encoded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_document: Option<String>,
    /// The key bound into the document, which is the key that signs verdicts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_public_key: Option<String>,
    /// The nonce echoed into the document, when the caller supplied one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// The manifest this enclave booted with, hex encoded.
    ///
    /// Convenience only: a client must compare the document against a manifest obtained
    /// from whoever approved the deployment, not against this one. See the module docs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_reported_manifest: Option<String>,
    /// Why the self-reported manifest is not sufficient on its own.
    pub manifest_caveat: &'static str,
}

/// Wording carried in every response so the caveat travels with the data.
const MANIFEST_CAVEAT: &str = "selfReportedManifest is what this enclave says it booted with. \
     Verifying the attestation document against it proves only that some genuine Nitro enclave \
     is running something. To learn which code is running, compare the document's PCRs against \
     a manifest obtained from whoever approved the deployment.";

/// Ask the NSM for a document binding `public_key`, and optionally a caller nonce.
///
/// `public_key` should be the key this app signs with, so a client can tie a signed verdict
/// to the attested enclave. `nonce` lets a caller prove freshness: a document echoing a
/// nonce they just chose cannot be a replay of an older one.
#[must_use]
pub fn attestation_material(
    public_key: &[u8],
    nonce: Option<&[u8]>,
    manifest: Option<&[u8]>,
) -> AttestationMaterial {
    let request = NsmRequest::Attestation {
        user_data: None,
        nonce: nonce.map(<[u8]>::to_vec),
        public_key: Some(public_key.to_vec()),
    };

    match Nsm.nsm_process_request(request) {
        NsmResponse::Attestation { document } => AttestationMaterial {
            available: true,
            unavailable_reason: None,
            attestation_document: Some(qos_hex::encode(&document)),
            bound_public_key: Some(qos_hex::encode(public_key)),
            nonce: nonce.map(qos_hex::encode),
            self_reported_manifest: manifest.map(qos_hex::encode),
            manifest_caveat: MANIFEST_CAVEAT,
        },
        // Anything else means no document. Outside an enclave this is the ioctl failing,
        // which is expected and must not read as a malfunction.
        other => AttestationMaterial {
            available: false,
            unavailable_reason: Some(format!(
                "the Nitro Secure Module did not return an attestation document ({other:?}). \
                 Outside a Nitro enclave there is no NSM device, so this is expected when \
                 running locally."
            )),
            attestation_document: None,
            bound_public_key: Some(qos_hex::encode(public_key)),
            nonce: nonce.map(qos_hex::encode),
            self_reported_manifest: manifest.map(qos_hex::encode),
            manifest_caveat: MANIFEST_CAVEAT,
        },
    }
}

/// Read the manifest QOS wrote for this enclave, if it is present.
///
/// Returns `None` rather than failing: the manifest is a convenience for clients, and its
/// absence should not take the endpoint down.
#[must_use]
pub fn read_manifest() -> Option<Vec<u8>> {
    std::fs::read(qos_core::MANIFEST_FILE).ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Off the enclave there is no NSM device. The endpoint must still answer, and must say
    /// why, rather than surfacing this as a failure of the service.
    #[test]
    fn reports_unavailable_off_enclave_without_failing() {
        let material = attestation_material(&[1, 2, 3], None, None);

        // This test runs off-enclave, so no document is possible.
        assert!(!material.available);
        let reason = material.unavailable_reason.expect("a reason");
        assert!(
            reason.contains("Nitro"),
            "the reason should explain the absence: {reason}"
        );
        assert!(material.attestation_document.is_none());
    }

    /// Even when unavailable, the response still says which key would have been bound, so a
    /// caller can see what the document *would* have attested to.
    #[test]
    fn always_reports_the_key_it_would_bind() {
        let material = attestation_material(&[0xab, 0xcd], None, None);
        assert_eq!(material.bound_public_key.as_deref(), Some("abcd"));
    }

    #[test]
    fn echoes_a_caller_nonce_so_freshness_can_be_checked() {
        let material = attestation_material(&[1], Some(&[0xde, 0xad]), None);
        assert_eq!(material.nonce.as_deref(), Some("dead"));
    }

    /// The caveat has to travel with the data, not live only in documentation, because the
    /// mistake it guards against (trusting the server's own manifest) is invisible.
    #[test]
    fn the_manifest_caveat_is_always_present() {
        let material = attestation_material(&[1], None, Some(&[0x01, 0x02]));
        assert_eq!(material.self_reported_manifest.as_deref(), Some("0102"));
        assert!(material.manifest_caveat.contains("approved the deployment"));

        // And it is present even when no manifest was found, so the field is never a
        // silently-missing warning.
        let without = attestation_material(&[1], None, None);
        assert!(!without.manifest_caveat.is_empty());
    }
}
