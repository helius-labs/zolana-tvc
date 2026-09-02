use std::sync::Arc;

use qos_p256::P256Pair;
use zolana_keypair::SigningKey;
use zolana_tvc_protocol::constants::{
    API_VERSION, DEVNET_MAX_ENCRYPTED_REQUEST_BYTES, DEVNET_MAX_ENCRYPTED_RESPONSE_BYTES,
    TVC_APP_PROOF_TYPE,
};
use zolana_tvc_protocol::types::{
    ClientAuthorization, ClientAuthorizationScheme, ClientGrant, DecryptPayload, DecryptedPayload,
    ServiceInfo, WalletDescriptor,
};

use zolana_tvc_protocol::digest::state_digest;

use super::sealed::{seal, unseal, Roles};
use super::*;
use crate::custody::TurnkeyCustody;
use crate::Services;

/// A wallet key plus the seed its derivation message signs to.
struct TestWallet {
    secret: [u8; 32],
    public_key: [u8; 32],
    seed: [u8; 64],
}

fn test_wallet() -> TestWallet {
    let secret = *SigningKey::new_ed25519().secret_bytes();
    let key = ed25519_dalek::SigningKey::from_bytes(&secret);
    let public_key = key.verifying_key().to_bytes();
    let message = zolana_keypair::derivation::ed25519_derivation_message(&public_key);
    let seed = ed25519_dalek::Signer::sign(&key, &message).to_bytes();
    TestWallet {
        secret,
        public_key,
        seed,
    }
}

/// The failure of a result whose success value has no `Debug`.
fn failure<T>(result: Result<T, Failure>) -> Failure {
    match result {
        Ok(_) => panic!("expected a failure"),
        Err(failure) => failure,
    }
}

fn runtime() -> Runtime {
    let quorum = Arc::new(P256Pair::generate().expect("quorum"));
    Runtime {
        ephemeral: Arc::new(P256Pair::generate().expect("ephemeral")),
        custody: Arc::new(TurnkeyCustody::new(Arc::clone(&quorum))),
        quorum,
        provisioning_public: PROVISIONING_PUBLIC,
        services: Services::devnet(),
    }
}

fn descriptor(address: [u8; 32]) -> WalletDescriptor {
    WalletDescriptor {
        version: API_VERSION,
        security_domain_id: [0x11; 32],
        environment: Environment::Development,
        turnkey_organization_id: "00000000-0000-0000-0000-00000000000b".to_owned(),
        turnkey_wallet_id: "test".to_owned(),
        address: Pubkey::new_from_array(address).to_string(),
        allowed_clients: vec![ClientGrant {
            client_public_key: vec![0x04; 65],
            allowed_operations: OPERATIONS.to_vec(),
        }],
        provisioning_signature: vec![0u8; 64],
    }
}

fn request(operation: Operation, descriptor: WalletDescriptor) -> OperationRequest {
    OperationRequest {
        version: API_VERSION,
        request_id: [0x01; 32],
        issued_at_ms: 1_750_000_000_000,
        expires_at_ms: 1_750_000_060_000,
        target_release_id: "test".to_owned(),
        target_manifest_digest: [0x33; 32],
        target_executable_digest: [0x44; 32],
        quorum_key_id: "quorum".to_owned(),
        quorum_key_epoch: 1,
        wallet_descriptor: descriptor,
        sealed_wallet_state: None,
        client_response_public_key: vec![0u8; 65],
        operation,
        authorization: ClientAuthorization {
            client_key_id: "tvc-browser-p256-test".to_owned(),
            scheme: ClientAuthorizationScheme::P256Sha256,
            signature: vec![0u8; 64],
        },
    }
}

fn sealed_request(
    runtime: &Runtime,
    wallet: &TestWallet,
    operation: Operation,
) -> OperationRequest {
    let mut request = request(operation, descriptor(wallet.public_key));
    let (bytes, _) = seal(&request, runtime, wallet.public_key, wallet.seed).expect("seal");
    request.sealed_wallet_state = Some(bytes);
    request
}

#[test]
fn roles_come_only_from_the_wallets_own_derivation_signature() {
    let wallet = test_wallet();
    let roles = Roles::from_seed(&wallet.public_key, &wallet.seed).expect("roles");
    let address = roles.address().expect("address");
    assert_eq!(address.signing_pubkey, roles.owner);
    assert_eq!(address.viewing_pubkey, roles.viewing_key.pubkey());

    let other = test_wallet();
    assert_eq!(
        failure(Roles::from_seed(&other.public_key, &wallet.seed)),
        Failure::Invalid
    );
    let mut tampered = wallet.seed;
    tampered[7] ^= 1;
    assert_eq!(
        failure(Roles::from_seed(&wallet.public_key, &tampered)),
        Failure::Invalid
    );
}

#[test]
fn sealed_state_hides_the_seed_and_is_bound_to_descriptor_and_epoch() {
    let runtime = runtime();
    let wallet = test_wallet();
    let request = sealed_request(&runtime, &wallet, Operation::ViewTags);
    let sealed = request.sealed_wallet_state.clone().expect("sealed");
    assert!(!sealed.windows(64).any(|window| window == wallet.seed));

    let (roles, digest) = unseal(&request, &runtime).expect("unseal");
    assert_eq!(digest, state_digest(&sealed));
    assert_eq!(
        roles.address().expect("address"),
        Roles::from_seed(&wallet.public_key, &wallet.seed)
            .expect("roles")
            .address()
            .expect("address")
    );

    let mut other_epoch = request.clone();
    other_epoch.quorum_key_epoch = 2;
    assert_eq!(failure(unseal(&other_epoch, &runtime)), Failure::Invalid);

    let mut other_descriptor = request.clone();
    other_descriptor.wallet_descriptor.turnkey_wallet_id = "other".to_owned();
    assert_eq!(
        failure(unseal(&other_descriptor, &runtime)),
        Failure::Invalid
    );

    let mut other_grant = request.clone();
    other_grant.wallet_descriptor.allowed_clients[0].client_public_key = vec![0x05; 65];
    assert_eq!(failure(unseal(&other_grant, &runtime)), Failure::Invalid);

    let other_quorum = runtime_with_quorum(P256Pair::generate().expect("quorum"));
    assert_eq!(failure(unseal(&request, &other_quorum)), Failure::Invalid);

    let mut unsealed = request;
    unsealed.sealed_wallet_state = None;
    assert_eq!(failure(unseal(&unsealed, &runtime)), Failure::Invalid);
}

fn runtime_with_quorum(quorum: P256Pair) -> Runtime {
    let quorum = Arc::new(quorum);
    Runtime {
        ephemeral: Arc::new(P256Pair::generate().expect("ephemeral")),
        custody: Arc::new(TurnkeyCustody::new(Arc::clone(&quorum))),
        quorum,
        provisioning_public: PROVISIONING_PUBLIC,
        services: Services::devnet(),
    }
}

#[test]
fn the_same_seed_reseals_under_a_new_quorum_key_to_the_same_identity() {
    let wallet = test_wallet();
    let first = runtime();
    let second = runtime();
    let a = sealed_request(&first, &wallet, Operation::ViewTags);
    let b = sealed_request(&second, &wallet, Operation::ViewTags);
    assert_ne!(a.sealed_wallet_state, b.sealed_wallet_state);
    let (roles_a, _) = unseal(&a, &first).expect("first");
    let (roles_b, _) = unseal(&b, &second).expect("second");
    assert_eq!(view::tags(&roles_a), view::tags(&roles_b));
    assert_eq!(failure(unseal(&a, &second)), Failure::Invalid);
}

#[test]
fn view_tags_are_the_stable_recipient_tags() {
    let wallet = test_wallet();
    let roles = Roles::from_seed(&wallet.public_key, &wallet.seed).expect("roles");
    let OperationResult::ViewTags { view_tags } = view::tags(&roles) else {
        panic!("expected view tags");
    };
    assert_eq!(
        view_tags,
        vec![roles.viewing_key.recipient_bootstrap_view_tag()]
    );
}

#[test]
fn decrypt_opens_own_utxos_with_commitment_and_nullifier_and_marks_the_rest_unreadable() {
    use zolana_keypair::{random_blinding, random_salt, ViewingKey};
    use zolana_transaction::instructions::types::SppProofInputUtxo;
    use zolana_transaction::serialization::confidential::ConfidentialOutputPlaintext;
    use zolana_transaction::{Data, Utxo, SOL_ASSET_ID, SOL_MINT};

    let wallet = test_wallet();
    let roles = Roles::from_seed(&wallet.public_key, &wallet.seed).expect("roles");
    let transaction_key = ViewingKey::new();
    let salt = random_salt();
    let blinding = random_blinding();
    let plaintext = ConfidentialOutputPlaintext {
        asset_id: SOL_ASSET_ID,
        amount: 7,
        blinding,
        ring_program_id: None,
        data: Data::default(),
    }
    .serialize()
    .expect("plaintext");
    let encrypt = |recipient: &ViewingKey, slot: u32| DecryptPayload::Encrypted {
        ciphertext: transaction_key
            .encrypt_slot(&recipient.pubkey(), &plaintext, salt, slot)
            .expect("ciphertext"),
        transaction_viewing_public_key: transaction_key.pubkey().as_bytes().to_vec(),
        salt: salt.to_vec(),
        slot_index: u64::from(slot),
    };
    let mut payloads = vec![
        encrypt(&roles.viewing_key, 1),
        encrypt(&ViewingKey::new(), 2),
        DecryptPayload::Plain {
            asset: SOL_MINT.to_string(),
            amount: 7,
            blinding,
        },
    ];

    let OperationResult::Decrypt { payloads: results } =
        view::decrypt(&roles, &payloads, &[]).expect("decrypt")
    else {
        panic!("expected decrypted payloads");
    };
    let expected = SppProofInputUtxo::new(
        Utxo {
            owner: roles.owner,
            asset: SOL_MINT,
            amount: 7,
            blinding,
            ring_program_id: None,
            data: Data::default(),
        },
        &roles.nullifier_key,
    );
    let opened = |index| DecryptedPayload::Utxo {
        index,
        asset: SOL_MINT.to_string(),
        amount: 7,
        blinding,
        ring_program_id: None,
        commitment: expected.hash().expect("hash"),
        nullifier: expected.nullifier().expect("nullifier"),
    };
    assert_eq!(
        results,
        vec![
            opened(0),
            DecryptedPayload::Unreadable { index: 1 },
            opened(2)
        ]
    );

    assert_eq!(
        view::decrypt(&roles, &[], &[]).unwrap_err(),
        Failure::Invalid
    );
    let DecryptPayload::Encrypted {
        transaction_viewing_public_key,
        ..
    } = &mut payloads[0]
    else {
        panic!("expected an encrypted payload");
    };
    transaction_viewing_public_key.pop();
    assert_eq!(
        view::decrypt(&roles, &payloads[..1], &[]).unwrap_err(),
        Failure::Invalid
    );
}

fn unavailable_state() -> AppState {
    AppState::unavailable(ServiceInfo {
        version: API_VERSION,
        environment: Environment::Development,
        security_domain_id: [0; 32],
        release_id: "test".to_owned(),
        manifest_digest: [0; 32],
        executable_digest: [0; 32],
        quorum_public_key: Vec::new(),
        quorum_key_id: "quorum".to_owned(),
        quorum_key_epoch: 1,
        ephemeral_public_key: Vec::new(),
        supported_operations: OPERATIONS.to_vec(),
        max_encrypted_request_bytes: DEVNET_MAX_ENCRYPTED_REQUEST_BYTES,
        max_encrypted_response_bytes: DEVNET_MAX_ENCRYPTED_RESPONSE_BYTES,
        proof_type: TVC_APP_PROOF_TYPE.to_owned(),
        boot_proof_lookup_key: Vec::new(),
    })
}

#[test]
fn bootstrap_refuses_a_presented_state_and_the_rest_require_one() {
    let runtime = runtime();
    let wallet = test_wallet();
    let running = RunningEnclave {
        release_id: "test".to_owned(),
        manifest_digest: [0x33; 32],
        executable_digest: [0x44; 32],
        security_domain_id: [0x11; 32],
        quorum_key_id: "quorum".to_owned(),
        quorum_key_epoch: 1,
        environment: Environment::Development,
    };
    let state = unavailable_state();
    let with_state = sealed_request(&runtime, &wallet, Operation::Bootstrap);
    assert_eq!(
        failure(validate(&with_state, &running, &state, &runtime)),
        Failure::Invalid
    );
    for operation in [
        Operation::ViewTags,
        Operation::Decrypt {
            payloads: Vec::new(),
            assets: Vec::new(),
        },
    ] {
        let without_state = request(operation, descriptor(wallet.public_key));
        assert_eq!(
            failure(validate(&without_state, &running, &state, &runtime)),
            Failure::Invalid
        );
    }
}

#[test]
fn organization_ids_must_be_canonical_uuids() {
    assert!(is_canonical_uuid("00000000-0000-4000-8000-000000000001"));
    assert!(!is_canonical_uuid("00000000-0000-4000-8000-00000000000A"));
    assert!(!is_canonical_uuid("00000000000040008000000000000001"));
    assert!(!is_canonical_uuid("child-org"));
}

#[cfg(feature = "local-dev")]
mod local {
    //! The whole encrypted path against the testkit's local custody.

    use qos_p256::P256Pair;
    use serde::Deserialize;
    use zolana_tvc_protocol::auth::authorize_operation_request;
    use zolana_tvc_protocol::crypto::{
        parse_uncompressed_sec1, public_key_uncompressed, qos_decrypt, qos_encrypt,
        sign_p256_prehash, verify_p256_message, QosP256Public,
    };
    use zolana_tvc_protocol::digest::{descriptor_digest, request_digest, result_digest, sha256};
    use zolana_tvc_protocol::encoding::{decode_lower_hex_array, jcs_serialize, parse_strict_json};
    use zolana_tvc_protocol::types::{
        EncryptedRequest, EncryptedResponse, OperationProofPayload, SpendAction, SpendInput,
    };

    use super::*;
    use crate::{local_testkit_qos_seeds, local_unattested_state, LocalServiceConfig};

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Keys {
        provisioning_private_key_hex: String,
        client_private_key_hex: String,
        organization_id: String,
        wallet_id: String,
        security_domain_label: String,
        manifest_label: String,
        executable_label: String,
        release_id: String,
        quorum_key_id: String,
    }

    struct Harness {
        state: AppState,
        keys: Keys,
        wallet: TestWallet,
        client_secret: [u8; 32],
        response_secret: [u8; 32],
    }

    impl Harness {
        fn new() -> Self {
            let keys: Keys = serde_json::from_str(include_str!(
                "../../../../packages/tvc-wallet/src/local-testkit.json"
            ))
            .expect("testkit");
            let (ephemeral_seed, quorum_seed) = local_testkit_qos_seeds();
            let wallet = test_wallet();
            let state = local_unattested_state(
                P256Pair::from_master_seed(&ephemeral_seed.into()).expect("ephemeral"),
                P256Pair::from_master_seed(&quorum_seed.into()).expect("quorum"),
                wallet.secret,
                LocalServiceConfig {
                    solana_rpc_url: "http://127.0.0.1:1".to_owned(),
                    indexer_url: "http://127.0.0.1:1".to_owned(),
                    prover_url: "http://127.0.0.1:1".to_owned(),
                },
            );
            Self {
                state,
                client_secret: decode_lower_hex_array(&keys.client_private_key_hex)
                    .expect("client"),
                response_secret: [0x42; 32],
                keys,
                wallet,
            }
        }

        fn descriptor(&self) -> WalletDescriptor {
            let client_public = public_key_uncompressed(
                &p256::SecretKey::from_slice(&self.client_secret)
                    .expect("client scalar")
                    .public_key(),
            );
            let mut descriptor = WalletDescriptor {
                version: API_VERSION,
                security_domain_id: sha256(self.keys.security_domain_label.as_bytes()),
                environment: Environment::Development,
                turnkey_organization_id: self.keys.organization_id.clone(),
                turnkey_wallet_id: self.keys.wallet_id.clone(),
                address: Pubkey::new_from_array(self.wallet.public_key).to_string(),
                allowed_clients: vec![ClientGrant {
                    client_public_key: client_public.to_vec(),
                    allowed_operations: OPERATIONS.to_vec(),
                }],
                provisioning_signature: Vec::new(),
            };
            let provisioning: [u8; 32] =
                decode_lower_hex_array(&self.keys.provisioning_private_key_hex)
                    .expect("provisioner");
            descriptor.provisioning_signature = sign_p256_prehash(
                &provisioning,
                &descriptor_digest(&descriptor).expect("digest"),
            )
            .expect("descriptor signature")
            .to_vec();
            descriptor
        }

        fn request(&self, operation: Operation, sealed: Option<Vec<u8>>) -> OperationRequest {
            let info = &self.state.info;
            let now = now_ms().expect("clock");
            let descriptor = self.descriptor();
            let client_key_id = format!(
                "{CLIENT_KEY_ID_PREFIX}{}",
                hex::encode(
                    &Sha256::digest(&descriptor.allowed_clients[0].client_public_key)[..16]
                )
            );
            let response_public = public_key_uncompressed(
                &p256::SecretKey::from_slice(&self.response_secret)
                    .expect("response scalar")
                    .public_key(),
            );
            let request = OperationRequest {
                version: API_VERSION,
                request_id: sha256(b"request"),
                issued_at_ms: now,
                expires_at_ms: now + 60_000,
                target_release_id: self.keys.release_id.clone(),
                target_manifest_digest: sha256(self.keys.manifest_label.as_bytes()),
                target_executable_digest: sha256(self.keys.executable_label.as_bytes()),
                quorum_key_id: self.keys.quorum_key_id.clone(),
                quorum_key_epoch: 1,
                wallet_descriptor: descriptor,
                sealed_wallet_state: sealed,
                client_response_public_key: response_public.to_vec(),
                operation,
                authorization: ClientAuthorization {
                    client_key_id,
                    scheme: ClientAuthorizationScheme::P256Sha256,
                    signature: Vec::new(),
                },
            };
            assert_eq!(info.release_id, request.target_release_id);
            authorize_operation_request(request, &self.client_secret).expect("authorized")
        }

        /// Sends one request through the encrypted endpoint and opens the answer.
        async fn call(&self, request: &OperationRequest) -> Result<OperationResult, Failure> {
            let quorum =
                QosP256Public::from_bytes(&self.state.info.quorum_public_key).expect("quorum");
            let ciphertext = qos_encrypt(
                &quorum.encryption,
                jcs_serialize(request).expect("request").as_bytes(),
            )
            .expect("encrypt");
            let body = jcs_serialize(&EncryptedRequest {
                version: API_VERSION,
                quorum_key_id: request.quorum_key_id.clone(),
                quorum_key_epoch: request.quorum_key_epoch,
                ciphertext,
            })
            .expect("envelope");
            let response = execute(&self.state, body.as_bytes()).await?;
            let response: EncryptedResponse = parse_strict_json(&response).expect("response");
            assert_eq!(response.request_id, request.request_id);

            let proof = response.tvc_app_proof;
            let ephemeral = QosP256Public::from_bytes(&proof.public_key).expect("ephemeral");
            assert_eq!(proof.public_key, self.state.info.ephemeral_public_key);
            verify_p256_message(
                &ephemeral.signing,
                proof.proof_payload.as_bytes(),
                &proof.signature,
            )
            .expect("app proof signature");
            let payload: OperationProofPayload =
                parse_strict_json(&proof.proof_payload).expect("proof payload");
            assert_eq!(
                payload.request_digest,
                request_digest(request).expect("digest")
            );
            assert_eq!(
                payload.result_digest,
                result_digest(&response.encrypted_result)
            );
            assert_eq!(payload.operation, request.operation.kind());
            parse_uncompressed_sec1(&request.client_response_public_key).expect("response key");

            let plaintext =
                qos_decrypt(&self.response_secret, &response.encrypted_result).expect("result");
            Ok(
                parse_strict_json(std::str::from_utf8(plaintext.as_slice()).expect("utf8"))
                    .expect("result"),
            )
        }
    }

    #[tokio::test]
    async fn bootstrap_then_view_tags_through_the_encrypted_endpoint() {
        let harness = Harness::new();
        let bootstrap = harness.request(Operation::Bootstrap, None);
        let OperationResult::Bootstrap {
            solana_address,
            shielded_owner_hash,
            sealed_wallet_state,
            ..
        } = harness.call(&bootstrap).await.expect("bootstrap")
        else {
            panic!("expected a bootstrap result");
        };
        let roles =
            Roles::from_seed(&harness.wallet.public_key, &harness.wallet.seed).expect("roles");
        assert_eq!(
            solana_address,
            Pubkey::new_from_array(harness.wallet.public_key).to_string()
        );
        assert_eq!(
            shielded_owner_hash,
            roles
                .address()
                .expect("address")
                .owner_hash()
                .expect("owner hash")
        );
        assert!(!sealed_wallet_state
            .windows(64)
            .any(|window| window == harness.wallet.seed));

        let tags = harness.request(Operation::ViewTags, Some(sealed_wallet_state.clone()));
        assert_eq!(harness.call(&tags).await.expect("tags"), view::tags(&roles));

        // A bootstrap that presents a state, and a stateful operation that
        // presents none, are rejected before any key is touched.
        let stateful_bootstrap =
            harness.request(Operation::Bootstrap, Some(sealed_wallet_state.clone()));
        assert_eq!(
            harness.call(&stateful_bootstrap).await.unwrap_err(),
            Failure::Invalid
        );
        let stateless_tags = harness.request(Operation::ViewTags, None);
        assert_eq!(
            harness.call(&stateless_tags).await.unwrap_err(),
            Failure::Invalid
        );

        // Malformed spends are refused before the enclave reaches any service.
        let input = SpendInput {
            asset: zolana_transaction::SOL_MINT.to_string(),
            amount: 5,
            blinding: [7; 32],
        };
        let transfer = SpendAction::Transfer {
            recipient: roles.address().expect("address").to_bytes().to_vec(),
            asset: zolana_transaction::SOL_MINT.to_string(),
            amount: 1,
        };
        let spend = |tree: &str, inputs: Vec<SpendInput>, action: SpendAction| {
            harness.request(
                Operation::Spend {
                    tree: tree.to_owned(),
                    inputs,
                    action,
                    assets: Vec::new(),
                },
                Some(sealed_wallet_state.clone()),
            )
        };
        let tree = Pubkey::new_from_array([9; 32]).to_string();
        for request in [
            spend(&tree, Vec::new(), transfer.clone()),
            spend(&tree, vec![input.clone(); 6], transfer.clone()),
            spend("not-a-tree", vec![input.clone()], transfer.clone()),
            spend(
                &tree,
                vec![input.clone()],
                SpendAction::Transfer {
                    recipient: vec![0u8; 3],
                    asset: zolana_transaction::SOL_MINT.to_string(),
                    amount: 1,
                },
            ),
            spend(
                &tree,
                vec![input.clone()],
                SpendAction::Withdrawal {
                    recipient: Pubkey::new_from_array([3; 32]).to_string(),
                    asset: zolana_transaction::SOL_MINT.to_string(),
                    amount: 0,
                },
            ),
        ] {
            assert_eq!(harness.call(&request).await.unwrap_err(), Failure::Invalid);
        }
    }
}
