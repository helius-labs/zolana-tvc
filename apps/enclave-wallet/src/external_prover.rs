//! Closed external-prover profile for disposable devnet transfers.

use std::str::FromStr;

use solana_address::Address;
use zolana_client::{ClientError, ProofCompressed, TransferProofResult, ZolanaClient};
use zolana_tvc_protocol::types::reject_production_environment;
use zolana_tvc_protocol::{Environment, ErrorCode, TvcError};

/// Manifest-approved identifier for the only external prover profile.
pub const DEVNET_EXTERNAL_PROVER_PROFILE_ID: &str = "zolnet-devnet-external-http-v1";

/// Exact public prover origin selected by the development profile.
pub const DEVNET_EXTERNAL_PROVER_URL: &str =
    "http://zolnet-devnet-1779374825.eu-north-1.elb.amazonaws.com";

/// Exact Photon origin selected with the same development network profile.
pub const DEVNET_EXTERNAL_PHOTON_URL: &str =
    "http://zolnet-devnet-1779374825.eu-north-1.elb.amazonaws.com";

/// Default devnet pool tree used by the first transfer profile.
pub const DEVNET_DEFAULT_TREE: &str = "trEEbaNobcTESNmtsPBj3FX27q5sDCQePV2kb12FYho";

/// OCI artifact expected behind [`DEVNET_EXTERNAL_PROVER_URL`].
pub const DEVNET_EXTERNAL_PROVER_IMAGE: &str =
    "558215002830.dkr.ecr.eu-north-1.amazonaws.com/zolana-prover:sync-proofs-e9c75b6d67c9@sha256:07b4666bc4a6f7b557f4f39b9e82ea41034830f0ea76e9bb98ee5e0936cf5bfe";

/// Parsed proof client for the one approved plaintext development origin.
///
/// Construction rejects a production environment, and callers cannot supply a
/// URL. Network I/O starts only when [`Self::prove_default_ring`] is called.
pub struct ExternalProver {
    client: ZolanaClient<()>,
}

impl ExternalProver {
    pub fn for_environment(environment: Environment) -> Result<Self, TvcError> {
        reject_production_environment(environment)?;
        let output_tree = Address::from_str(DEVNET_DEFAULT_TREE)
            .map_err(|_| TvcError::new(ErrorCode::ChainInputInvalid))?;
        Ok(Self {
            client: ZolanaClient::from_urls_allowing_insecure_http(
                (),
                DEVNET_EXTERNAL_PHOTON_URL,
                DEVNET_EXTERNAL_PROVER_URL,
                output_tree,
            ),
        })
    }

    pub fn profile_id(&self) -> &'static str {
        DEVNET_EXTERNAL_PROVER_PROFILE_ID
    }

    pub fn prover_url(&self) -> &'static str {
        DEVNET_EXTERNAL_PROVER_URL
    }

    pub fn prover_image(&self) -> &'static str {
        DEVNET_EXTERNAL_PROVER_IMAGE
    }

    /// Generate and locally verify a default-ring Ed25519 transfer proof.
    ///
    /// The returned proof is safe to put into transaction construction only
    /// after the shape-specific local verification in this method succeeds.
    pub async fn prove_default_ring(
        &self,
        result: &TransferProofResult,
    ) -> Result<ProofCompressed, ClientError> {
        if result.inputs.ring_program_id.bits() != 0 {
            return Err(ClientError::ProofVerification(
                "development prover profile accepts only the default ring".to_owned(),
            ));
        }
        if !result
            .inputs
            .inputs
            .iter()
            .any(|input| input.is_dummy.bits() == 0)
        {
            return Err(ClientError::NoInputs);
        }

        self.client.prove_confidential_transfer_result(result).await
    }
}

#[cfg(test)]
mod tests {
    use zolana_tvc_protocol::{Environment, ErrorCode};

    use super::*;

    #[test]
    fn profile_is_closed_and_devnet_only() {
        let profile = ExternalProver::for_environment(Environment::Development).unwrap();
        assert_eq!(profile.profile_id(), "zolnet-devnet-external-http-v1");
        assert_eq!(
            profile.prover_url(),
            "http://zolnet-devnet-1779374825.eu-north-1.elb.amazonaws.com"
        );
        assert_eq!(
            profile.prover_image(),
            "558215002830.dkr.ecr.eu-north-1.amazonaws.com/zolana-prover:sync-proofs-e9c75b6d67c9@sha256:07b4666bc4a6f7b557f4f39b9e82ea41034830f0ea76e9bb98ee5e0936cf5bfe"
        );

        let error = ExternalProver::for_environment(Environment::Production)
            .err()
            .expect("production profile is rejected");
        assert_eq!(error.code, ErrorCode::ProductionClaimRejected);
    }
}
