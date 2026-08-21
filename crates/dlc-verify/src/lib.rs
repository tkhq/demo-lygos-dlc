//! DLC verification service for Turnkey Verifiable Cloud.
//!
//! Verifies Lygos loan contracts — message structure, oracle announcement signature, and
//! CET adaptor signatures — and confirms the collateral transaction is on chain, then
//! signs the combined verdict with the enclave's attested key.

pub mod btc;
pub mod cli;
pub mod client;
pub mod decision;
pub mod dlc;
pub mod fixtures;
mod handlers;
pub mod response;
pub mod router;
mod state;
