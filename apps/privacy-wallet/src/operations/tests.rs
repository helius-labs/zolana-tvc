use super::*;
use solana_instruction::{AccountMeta, Instruction};

use qos_p256::P256Pair;
use zolana_tvc_protocol::types::{
    ClientAuthorizationScheme, ClientAuthorizationV1, ClientGrantV1, SppMessageV1, SppPlanOutputV1,
    SppShapeV1, WalletDescriptorV1,
};

const TEST_SEED: [u8; 64] = [0x5a; 64];

fn runtime_keys() -> RuntimeKeys {
    RuntimeKeys {
        ephemeral: Arc::new(P256Pair::generate().expect("ephemeral")),
        quorum: Arc::new(P256Pair::generate().expect("quorum")),
    }
}

fn descriptor() -> WalletDescriptorV1 {
    WalletDescriptorV1 {
        version: API_VERSION,
        security_domain_id: [0x11; 32],
        environment: Environment::Development,
        turnkey_organization_id: "00000000-0000-0000-0000-00000000000b".to_owned(),
        turnkey_wallet_id: "keyholder-test".to_owned(),
        address: Pubkey::new_from_array([0x22; 32]).to_string(),
        allowed_clients: vec![ClientGrantV1 {
            client_public_key: vec![0x04; 65],
            allowed_operations: KEYHOLDER_OPERATIONS.to_vec(),
        }],
        provisioning_signature: vec![0u8; 64],
    }
}

fn request(operation: OperationV1, descriptor: WalletDescriptorV1) -> OperationRequestV1 {
    OperationRequestV1 {
        version: API_VERSION,
        request_id: [0x01; 32],
        issued_at_ms: 1_750_000_000_000,
        expires_at_ms: 1_750_000_060_000,
        target_release_id: "keyholder-test".to_owned(),
        target_manifest_digest: [0x33; 32],
        target_executable_digest: [0x44; 32],
        quorum_key_id: "keyholder-quorum".to_owned(),
        quorum_key_epoch: 1,
        wallet_descriptor: descriptor,
        sealed_wallet_state: None,
        client_response_public_key: vec![0u8; 65],
        operation,
        authorization: ClientAuthorizationV1 {
            client_key_id: "tvc-browser-p256-test".to_owned(),
            scheme: ClientAuthorizationScheme::P256Sha256,
            signature: vec![0u8; 64],
        },
    }
}

/// Seals `TEST_SEED` and returns a request that presents the resulting blob.
fn sealed_request(keys: &RuntimeKeys, operation: OperationV1) -> OperationRequestV1 {
    let descriptor = descriptor();
    let bootstrap = request(OperationV1::BootstrapKeyholder, descriptor.clone());
    let (_, bytes, _) = seal_state(
        keys,
        KeyStatePlaintextV1 {
            version: API_VERSION,
            quorum_key_id: bootstrap.quorum_key_id.clone(),
            quorum_key_epoch: bootstrap.quorum_key_epoch,
            wallet_id: descriptor.wallet_id(),
            descriptor_digest: descriptor_digest_from_wallet(&descriptor).expect("digest"),
            ed25519_public_key: [0x22; 32],
            derivation_suite: DERIVATION_SUITE.to_owned(),
            derivation_seed: TEST_SEED,
        },
    )
    .expect("seal");

    let mut next = request(operation, descriptor);
    next.sealed_wallet_state = Some(bytes);
    next
}

fn ring_intent(program: Pubkey) -> SpendIntentV1 {
    SpendIntentV1 {
        source: PrivateDomainV1::Ring {
            program_id: program.to_string(),
            lookup_table: Pubkey::new_from_array([0x44; 32]).to_string(),
        },
        settlement: SpendSettlementV1::Withdrawal {
            asset: AssetV1::Sol,
            recipient: Pubkey::new_from_array([0x55; 32]).to_string(),
            amount: 1,
        },
        input_commitments: Vec::new(),
    }
}

fn wallet(payer: Pubkey) -> ValidatedWallet<'static> {
    ValidatedWallet {
        organization_id: "00000000-0000-0000-0000-000000000000",
        sign_with: "payer",
        address: payer,
        expected_ed25519_public_key: payer.to_bytes(),
    }
}

fn private_program_message(
    payer: Address,
    program: Address,
    input_tree: Address,
    transact: &[u8],
    extra_accounts: Vec<AccountMeta>,
    extra_instructions: Vec<Instruction>,
) -> VersionedMessage {
    let mut accounts = vec![
        AccountMeta::new(payer, true),
        AccountMeta::new(input_tree, false),
        AccountMeta::new_readonly(Address::new_from_array(SHIELDED_POOL_PROGRAM_ID), false),
        AccountMeta::new_readonly(Address::default(), false),
    ];
    accounts.extend(extra_accounts);
    let instruction = Instruction {
        program_id: program,
        accounts,
        data: [b"program-prefix".as_slice(), transact].concat(),
    };
    let mut instructions = vec![instruction];
    instructions.extend(extra_instructions);
    VersionedMessage::V0(
        v0::Message::try_compile(&payer, &instructions, &[], solana_hash::Hash::default())
            .expect("compile program transaction"),
    )
}

#[test]
fn reusable_lookup_table_can_omit_a_dynamic_withdrawal_recipient() {
    let payer = Address::new_from_array([0x61; 32]);
    let stable_ring_account = Address::new_from_array([0x62; 32]);
    let recipient = Address::new_from_array([0x63; 32]);
    let program = Address::new_from_array([0x64; 32]);
    let table_address = Address::new_from_array([0x65; 32]);
    let instruction = Instruction {
        program_id: program,
        accounts: vec![
            AccountMeta::new_readonly(stable_ring_account, false),
            AccountMeta::new(recipient, false),
        ],
        data: Vec::new(),
    };
    let table = AddressLookupTableAccount {
        key: table_address,
        addresses: vec![stable_ring_account],
    };

    let message = v0::Message::try_compile(
        &payer,
        &[instruction],
        &[table],
        solana_hash::Hash::default(),
    )
    .expect("compile with recipient outside reusable table");

    assert!(message.account_keys.contains(&recipient));
    assert!(!message.account_keys.contains(&stable_ring_account));
    assert_eq!(message.address_table_lookups.len(), 1);
}

#[test]
fn bootstrap_rejects_presented_state() {
    let keys = runtime_keys();

    assert!(operation_state_fields_are_valid(&request(
        OperationV1::BootstrapKeyholder,
        descriptor(),
    )));
    assert!(!operation_state_fields_are_valid(&sealed_request(
        &keys,
        OperationV1::BootstrapKeyholder,
    )));
}

#[test]
fn stateful_keyholder_operations_require_the_sealed_state() {
    let keys = runtime_keys();
    let tags = OperationV1::DeriveViewTags;
    let complete = sealed_request(&keys, tags.clone());
    assert!(operation_state_fields_are_valid(&complete));

    let mut missing_blob = complete.clone();
    missing_blob.sealed_wallet_state = None;
    assert!(!operation_state_fields_are_valid(&missing_blob));

    assert!(!operation_state_fields_are_valid(&request(
        tags,
        descriptor()
    )));
    assert!(operation_state_fields_are_valid(&sealed_request(
        &keys,
        OperationV1::DecryptUtxos {
            payloads: Vec::new(),
            include_spendable_outputs: true,
        },
    )));
    assert!(operation_state_fields_are_valid(&sealed_request(
        &keys,
        OperationV1::AuthorizeSpend {
            spend: AuthorizeSpendRequestV1::Prepare {
                plan: SpendPlanV1::Direct {
                    transition: ring_intent(Pubkey::new_unique()),
                },
            },
        },
    )));
}

#[test]
fn sealed_key_state_hides_the_seed_and_round_trips() {
    let keys = runtime_keys();
    let request = sealed_request(&keys, OperationV1::BootstrapKeyholder);
    let sealed = request.sealed_wallet_state.as_deref().expect("sealed");

    // The blob the browser stores must not contain the seed in the clear.
    assert!(sealed
        .windows(TEST_SEED.len())
        .all(|window| window != TEST_SEED));

    let (inner, _) = unseal_state(&request, &keys, sealed).expect("unseal");
    assert_eq!(inner.derivation_seed, TEST_SEED);
    assert_eq!(inner.derivation_suite, DERIVATION_SUITE);
}

#[test]
fn prepared_spend_capsule_is_bound_to_wallet_release_state_and_transaction() {
    let keys = runtime_keys();
    let request = sealed_request(&keys, OperationV1::DeriveViewTags);
    let state_digest_bytes = state_digest(
        request
            .sealed_wallet_state
            .as_deref()
            .expect("sealed state"),
    );
    let transaction_digest = artifact_digest(b"one exact unsigned transaction");
    let expires_at_ms = current_time_ms().expect("clock") + 60_000;
    let descriptor_digest =
        descriptor_digest_from_wallet(&request.wallet_descriptor).expect("descriptor digest");
    let capsule = seal_spend_authorization(
        &keys,
        SpendAuthorizationPlaintextV1 {
            version: API_VERSION,
            quorum_key_id: request.quorum_key_id.clone(),
            quorum_key_epoch: request.quorum_key_epoch,
            wallet_id: request.wallet_descriptor.wallet_id(),
            descriptor_digest,
            state_digest: state_digest_bytes,
            target_release_id: request.target_release_id.clone(),
            target_manifest_digest: request.target_manifest_digest,
            target_executable_digest: request.target_executable_digest,
            prepare_request_id: [41; 32],
            expires_at_ms,
            artifact: SpendAuthorizationArtifactV1::ExactTransaction { transaction_digest },
            shielded_balance_before: 99,
        },
    )
    .expect("seal authorization");

    let opened = unseal_spend_authorization(&request, &keys, &capsule, state_digest_bytes)
        .expect("open authorization");
    assert!(matches!(
        opened.artifact,
        SpendAuthorizationArtifactV1::ExactTransaction {
            transaction_digest: opened_digest,
        } if opened_digest == transaction_digest
    ));
    assert_eq!(opened.shielded_balance_before, 99);

    let mut wrong_release = request.clone();
    wrong_release.target_release_id = "another-release".to_owned();
    assert!(
        unseal_spend_authorization(&wrong_release, &keys, &capsule, state_digest_bytes,).is_err()
    );

    let mut tampered = capsule;
    *tampered.last_mut().expect("capsule byte") ^= 1;
    assert!(unseal_spend_authorization(&request, &keys, &tampered, state_digest_bytes,).is_err());
}

#[test]
fn generic_capsule_seals_the_exact_program_and_transact() {
    let keys = runtime_keys();
    let request = sealed_request(&keys, OperationV1::DeriveViewTags);
    let state_digest_bytes = state_digest(
        request
            .sealed_wallet_state
            .as_deref()
            .expect("sealed state"),
    );
    let program_id = [0x35; 32];
    let prepared_transact = b"one exact spp transact".to_vec();
    let transact_digest = artifact_digest(&prepared_transact);
    let capsule = seal_spend_authorization(
        &keys,
        SpendAuthorizationPlaintextV1 {
            version: API_VERSION,
            quorum_key_id: request.quorum_key_id.clone(),
            quorum_key_epoch: request.quorum_key_epoch,
            wallet_id: request.wallet_descriptor.wallet_id(),
            descriptor_digest: descriptor_digest_from_wallet(&request.wallet_descriptor)
                .expect("descriptor digest"),
            state_digest: state_digest_bytes,
            target_release_id: request.target_release_id.clone(),
            target_manifest_digest: request.target_manifest_digest,
            target_executable_digest: request.target_executable_digest,
            prepare_request_id: [0x36; 32],
            expires_at_ms: current_time_ms().expect("clock") + 60_000,
            artifact: SpendAuthorizationArtifactV1::Spp {
                program_id,
                input_tree: [0x39; 32],
                program_authorities: vec![[0x3a; 32]],
                plan_digest: [0x37; 32],
                prepared_transact: prepared_transact.clone(),
                transact_digest,
                private_tx_hash: [0x38; 32],
            },
            shielded_balance_before: 7,
        },
    )
    .expect("seal authorization");

    let opened = unseal_spend_authorization(&request, &keys, &capsule, state_digest_bytes)
        .expect("open authorization");
    assert!(matches!(
        opened.artifact,
        SpendAuthorizationArtifactV1::Spp {
            program_id: opened_program,
            prepared_transact: opened_transact,
            transact_digest: opened_digest,
            ..
        } if opened_program == program_id
            && opened_transact == prepared_transact
            && opened_digest == transact_digest
    ));
}

#[test]
fn generic_transaction_binds_private_hash_and_allows_normal_composition() {
    let payer = Address::new_from_array([0x41; 32]);
    let program = Address::new_from_array([0x42; 32]);
    let input_tree = Address::new_from_array([0x44; 32]);
    let private_tx_hash = [0x47; 32];
    let valid = private_program_message(
        payer,
        program,
        input_tree,
        &private_tx_hash,
        Vec::new(),
        vec![Instruction {
            program_id: Address::new_from_array([0x70; 32]),
            accounts: vec![AccountMeta::new_readonly(payer, true)],
            data: b"another user-approved instruction".to_vec(),
        }],
    );
    assert!(validate_private_program_message(
        payer,
        program,
        input_tree,
        &[],
        private_tx_hash,
        &valid,
        &LoadedAddresses::default(),
    )
    .is_ok());

    let substituted = private_program_message(
        payer,
        program,
        input_tree,
        b"different-transact",
        Vec::new(),
        Vec::new(),
    );
    assert!(validate_private_program_message(
        payer,
        program,
        input_tree,
        &[],
        private_tx_hash,
        &substituted,
        &LoadedAddresses::default(),
    )
    .is_err());

    let ambiguous = private_program_message(
        payer,
        program,
        input_tree,
        &[private_tx_hash, private_tx_hash].concat(),
        Vec::new(),
        Vec::new(),
    );
    assert!(validate_private_program_message(
        payer,
        program,
        input_tree,
        &[],
        private_tx_hash,
        &ambiguous,
        &LoadedAddresses::default(),
    )
    .is_err());

    let program_authority = Address::new_from_array([0x46; 32]);
    assert!(validate_private_program_message(
        payer,
        program,
        input_tree,
        &[program_authority.to_bytes()],
        private_tx_hash,
        &valid,
        &LoadedAddresses::default(),
    )
    .is_err());
    let with_program_authority = private_program_message(
        payer,
        program,
        input_tree,
        &private_tx_hash,
        vec![AccountMeta::new_readonly(program_authority, false)],
        Vec::new(),
    );
    assert!(validate_private_program_message(
        payer,
        program,
        input_tree,
        &[program_authority.to_bytes()],
        private_tx_hash,
        &with_program_authority,
        &LoadedAddresses::default(),
    )
    .is_ok());
    let reserved = private_program_message(
        payer,
        Address::default(),
        input_tree,
        &private_tx_hash,
        Vec::new(),
        Vec::new(),
    );
    assert!(validate_private_program_message(
        payer,
        Address::default(),
        input_tree,
        &[],
        private_tx_hash,
        &reserved,
        &LoadedAddresses::default(),
    )
    .is_err());
}

#[test]
fn generic_program_authority_seeds_are_bound_to_the_target() {
    let program = Pubkey::new_from_array([0x51; 32]);
    let seed = b"order_authority".to_vec();
    let (expected, bump) = Pubkey::find_program_address(&[seed.as_slice()], &program);
    let derived =
        derive_program_authority(&program, &[seed, vec![bump]]).expect("derive declared authority");
    assert_eq!(derived.to_bytes(), expected.to_bytes());
    assert!(derive_program_authority(&program, &[]).is_err());
    assert!(derive_program_authority(&program, &[vec![0; 33]]).is_err());
}

#[test]
fn direct_route_is_derived_from_source_and_destination_domains() {
    let ring_a = PrivateDomainV1::Ring {
        program_id: Pubkey::new_from_array([0x61; 32]).to_string(),
        lookup_table: Pubkey::new_from_array([0x62; 32]).to_string(),
    };
    let ring_b = PrivateDomainV1::Ring {
        program_id: Pubkey::new_from_array([0x63; 32]).to_string(),
        lookup_table: Pubkey::new_from_array([0x64; 32]).to_string(),
    };
    let transfer = |source: PrivateDomainV1, destination: PrivateDomainV1| SpendIntentV1 {
        source,
        settlement: SpendSettlementV1::Transfer {
            asset: AssetV1::Sol,
            recipient: Pubkey::new_from_array([0x65; 32]).to_string(),
            amount: 1,
            destination,
        },
        input_commitments: Vec::new(),
    };

    let enters = transfer(PrivateDomainV1::Default, ring_a.clone());
    assert_eq!(
        transaction_ring(&enters).expect("default to ring"),
        domain_ring(&ring_a),
    );
    let same_ring = transfer(ring_a.clone(), ring_a.clone());
    assert_eq!(
        transaction_ring(&same_ring).expect("same ring"),
        domain_ring(&ring_a),
    );
    assert!(transaction_ring(&transfer(ring_a, ring_b)).is_err());

    let consolidate = SpendIntentV1 {
        source: PrivateDomainV1::Default,
        settlement: SpendSettlementV1::Consolidate {
            asset: AssetV1::Sol,
        },
        input_commitments: Vec::new(),
    };
    assert_eq!(transaction_ring(&consolidate).expect("default merge"), None);
}

#[test]
fn sealed_key_state_is_bound_to_its_descriptor_and_quorum_epoch() {
    let keys = runtime_keys();
    let base = sealed_request(&keys, OperationV1::BootstrapKeyholder);
    let sealed = base.sealed_wallet_state.clone().expect("sealed");

    // Each mutation is one thing a stolen blob could be replayed against.
    let mut wrong_epoch = base.clone();
    wrong_epoch.quorum_key_epoch = 2;
    assert!(unseal_state(&wrong_epoch, &keys, &sealed).is_err());

    let mut wrong_quorum_key = base.clone();
    wrong_quorum_key.quorum_key_id = "other-quorum".to_owned();
    assert!(unseal_state(&wrong_quorum_key, &keys, &sealed).is_err());

    let mut wrong_wallet = base.clone();
    wrong_wallet.wallet_descriptor.turnkey_wallet_id = "someone-else".to_owned();
    assert!(unseal_state(&wrong_wallet, &keys, &sealed).is_err());

    // A descriptor change the envelope cannot see is caught by the inner
    // descriptor digest, which is why the check is done twice.
    let mut wrong_descriptor = base.clone();
    wrong_descriptor.wallet_descriptor.turnkey_organization_id =
        "00000000-0000-0000-0000-00000000000f".to_owned();
    assert!(unseal_state(&wrong_descriptor, &keys, &sealed).is_err());

    // A different enclave's Quorum key cannot open it at all.
    assert!(unseal_state(&base, &runtime_keys(), &sealed).is_err());
}

#[test]
fn the_same_seed_reseals_under_a_new_quorum_key_without_becoming_portable() {
    // The sealed key state is a replaceable cache, not the root of recovery.
    // A new release with a new Quorum key re-runs bootstrap, gets the same
    // deterministic Turnkey signature, and seals the same seed afresh.
    let old_keys = runtime_keys();
    let new_keys = runtime_keys();

    let old_request = sealed_request(&old_keys, OperationV1::BootstrapKeyholder);
    let new_request = sealed_request(&new_keys, OperationV1::BootstrapKeyholder);
    let old_sealed = old_request.sealed_wallet_state.clone().expect("old");
    let new_sealed = new_request.sealed_wallet_state.clone().expect("new");

    // Different Quorum keys must produce different blobs...
    assert_ne!(old_sealed, new_sealed);
    // ...that nonetheless recover the identical seed, which is what makes
    // the identity survive the rotation.
    let (old_inner, _) = unseal_state(&old_request, &old_keys, &old_sealed).expect("old");
    let (new_inner, _) = unseal_state(&new_request, &new_keys, &new_sealed).expect("new");
    assert_eq!(old_inner.derivation_seed, new_inner.derivation_seed);
    assert_eq!(
        derivation::expand_roles(&old_inner.derivation_seed, Curve::Ed25519)
            .expect("old roles")
            .1
            .pubkey()
            .as_bytes(),
        derivation::expand_roles(&new_inner.derivation_seed, Curve::Ed25519)
            .expect("new roles")
            .1
            .pubkey()
            .as_bytes(),
    );

    // Neither enclave can open the other's blob. Losing a blob is therefore
    // survivable, but a blob is never portable between deployments.
    assert!(unseal_state(&new_request, &new_keys, &old_sealed).is_err());
    assert!(unseal_state(&old_request, &old_keys, &new_sealed).is_err());
}

#[test]
fn view_tags_are_the_stable_tags_a_wallet_is_found_by() {
    // These are the tags the indexer is queried with, so they must equal
    // what a wallet holding the same viewing key would compute. Deriving a
    // window of sender tags instead -- which an earlier version did -- is
    // well-formed and finds nothing, because no query uses that family.
    let keys = runtime_keys();
    let request = sealed_request(&keys, OperationV1::DeriveViewTags);
    let (result, digest) = derive_view_tags(&request, &keys).expect("tags");
    assert_eq!(
        digest,
        state_digest(request.sealed_wallet_state.as_deref().expect("sealed"))
    );

    let (_, viewing_key) = derivation::expand_roles(&TEST_SEED, Curve::Ed25519).expect("expand");
    let OperationResultV1::DeriveViewTags { view_tags } = result else {
        panic!("wrong result variant");
    };
    assert_eq!(view_tags, vec![viewing_key.recipient_bootstrap_view_tag()]);

    // Stable, not positional: asking twice answers the same.
    let (again, _) = derive_view_tags(&request, &keys).expect("tags");
    let OperationResultV1::DeriveViewTags { view_tags: repeat } = again else {
        panic!("wrong result variant");
    };
    assert_eq!(repeat, view_tags);

    // The identity tag is deliberately absent: it derives from the signing
    // public key, so the client computes it without asking.
    assert_eq!(view_tags.len(), 1);
}

#[tokio::test]
async fn decrypt_returns_plaintext_without_asserting_ownership() {
    let keys = runtime_keys();
    let (_, viewing_key) = derivation::expand_roles(&TEST_SEED, Curve::Ed25519).expect("expand");
    let sender = ViewingKey::new();
    let salt: Salt = [0x7c; 16];
    let mine = sender
        .encrypt_slot(&viewing_key.pubkey(), b"utxo-plaintext", salt, 2)
        .expect("encrypt");
    let ring = sender
        .encrypt_ring_deposit(&viewing_key.pubkey(), b"ring-plaintext", salt)
        .expect("encrypt ring");
    let stranger = sender
        .encrypt_slot(&ViewingKey::new().pubkey(), b"not-yours", salt, 2)
        .expect("encrypt other");

    let payloads = vec![
        EncryptedPayloadV1::Utxo {
            ciphertext: mine,
            transaction_viewing_public_key: sender.pubkey().as_bytes().to_vec(),
            salt: salt.to_vec(),
            slot_index: 2,
        },
        EncryptedPayloadV1::Utxo {
            ciphertext: stranger,
            transaction_viewing_public_key: sender.pubkey().as_bytes().to_vec(),
            salt: salt.to_vec(),
            slot_index: 2,
        },
        EncryptedPayloadV1::RingDeposit {
            ciphertext: ring,
            transaction_viewing_public_key: sender.pubkey().as_bytes().to_vec(),
            salt: salt.to_vec(),
        },
    ];
    let request = sealed_request(
        &keys,
        OperationV1::DecryptUtxos {
            payloads: payloads.clone(),
            include_spendable_outputs: false,
        },
    );
    let payer = Pubkey::new_from_array([0x22; 32]);
    let (result, _) = decrypt_utxos(&request, &wallet(payer), &keys, &payloads, false)
        .await
        .expect("decrypt");
    let OperationResultV1::DecryptUtxos {
        payloads: results,
        spendable_outputs,
    } = result
    else {
        panic!("wrong result variant");
    };
    assert_eq!(spendable_outputs, None);

    assert_eq!(
        results.first(),
        Some(&DecryptedPayloadV1::Plaintext {
            index: 0,
            plaintext: b"utxo-plaintext".to_vec(),
        })
    );
    assert_eq!(
        results.get(2),
        Some(&DecryptedPayloadV1::Plaintext {
            index: 2,
            plaintext: b"ring-plaintext".to_vec(),
        })
    );

    // The transport cipher has no authentication tag, so a payload for a
    // different wallet decrypts to garbage instead of failing. This
    // operation must not pretend otherwise: it returns bytes and leaves the
    // ownership decision to the caller, which checks the deserialized owner.
    let Some(DecryptedPayloadV1::Plaintext { plaintext, .. }) = results.get(1) else {
        panic!("a foreign payload still yields bytes, it does not error");
    };
    assert_ne!(plaintext.as_slice(), b"not-yours");
    assert_eq!(plaintext.len(), b"not-yours".len());
}

#[tokio::test]
async fn decrypt_batches_are_bounded_and_reject_malformed_public_material() {
    let keys = runtime_keys();
    let request = sealed_request(&keys, OperationV1::BootstrapKeyholder);
    let payer = Pubkey::new_from_array([0x22; 32]);
    let target = wallet(payer);
    assert!(decrypt_utxos(&request, &target, &keys, &[], false)
        .await
        .is_err());

    let filler = EncryptedPayloadV1::RingDeposit {
        ciphertext: vec![0u8; 16],
        transaction_viewing_public_key: vec![0x02; 33],
        salt: vec![0x00; 16],
    };
    let oversized = vec![filler.clone(); (MAX_DECRYPT_PAYLOADS_PER_BATCH + 1) as usize];
    assert!(decrypt_utxos(&request, &target, &keys, &oversized, false)
        .await
        .is_err());

    // A wrong-length viewing key or salt is a malformed request, not a
    // ciphertext that happens to belong to someone else.
    assert!(decrypt_utxos(
        &request,
        &target,
        &keys,
        &[EncryptedPayloadV1::RingDeposit {
            ciphertext: vec![0u8; 16],
            transaction_viewing_public_key: vec![0x02; 32],
            salt: vec![0x00; 16],
        }],
        false,
    )
    .await
    .is_err());
    assert!(decrypt_utxos(
        &request,
        &target,
        &keys,
        &[EncryptedPayloadV1::RingDeposit {
            ciphertext: vec![0u8; 16],
            transaction_viewing_public_key: vec![0x02; 33],
            salt: vec![0x00; 8],
        }],
        false,
    )
    .await
    .is_err());
}

#[tokio::test]
async fn oracle_operations_require_a_sealed_state() {
    let keys = runtime_keys();
    let bare = request(OperationV1::BootstrapKeyholder, descriptor());
    assert!(derive_view_tags(&bare, &keys).is_err());
    let payer = Pubkey::new_from_array([0x22; 32]);
    assert!(decrypt_utxos(
        &bare,
        &wallet(payer),
        &keys,
        &[EncryptedPayloadV1::RingDeposit {
            ciphertext: vec![0u8; 16],
            transaction_viewing_public_key: vec![0x02; 33],
            salt: vec![0x00; 16],
        }],
        false,
    )
    .await
    .is_err());
}

#[tokio::test]
async fn bootstrap_refuses_to_continue_a_presented_state() {
    // Accepting one would let a caller choose which key state a fresh
    // derivation appears to follow. The guard runs before any Turnkey call,
    // so this test needs no network.
    let keys = runtime_keys();
    let request = sealed_request(&keys, OperationV1::BootstrapKeyholder);
    let payer = Pubkey::new_from_array([0x22; 32]);
    assert!(bootstrap_keyholder(&request, &wallet(payer), &keys)
        .await
        .is_err());
}

#[test]
fn descriptor_ids_must_be_lowercase_uuids() {
    assert!(is_uuid("a7db47e5-baca-41df-9c5a-e1ca746e6c37"));
    assert!(!is_uuid("A7db47e5-baca-41df-9c5a-e1ca746e6c37"));
    assert!(!is_uuid("../../wallet-organization"));
}

fn generic_plan(now_ms: u64) -> SppPlanV1 {
    SppPlanV1 {
        program_id: Pubkey::new_from_array([0x99; 32]).to_string(),
        input_tree: Pubkey::new_from_array([0x66; 32]).to_string(),
        shape: SppShapeV1 {
            inputs: 1,
            outputs: 1,
        },
        inputs: vec![SppPlanInputV1::Wallet {
            commitment: [0x77; 32],
        }],
        program_authorities: Vec::new(),
        outputs: vec![sample_output()],
        messages: Vec::new(),
        expires_at_ms: now_ms + 100_000,
    }
}

fn sample_output() -> SppPlanOutputV1 {
    SppPlanOutputV1 {
        recipient: "recipient".to_owned(),
        asset: AssetV1::Sol,
        amount: 1,
        blinding: [0x88; 32],
        data: Vec::new(),
        data_hash: None,
        memo: Vec::new(),
    }
}

/// Every case below must be refused before the first outbound call.
#[tokio::test]
async fn generic_spp_rejects_malformed_plans_before_any_outbound_call() {
    let keys = runtime_keys();
    let request = sealed_request(&keys, OperationV1::DeriveViewTags);
    let payer = Pubkey::new_from_array([0x22; 32]);
    let target = wallet(payer);
    let now_ms = current_time_ms().expect("clock");

    let mut plans = Vec::new();
    let mut empty_inputs = generic_plan(now_ms);
    empty_inputs.inputs.clear();
    plans.push(("empty inputs", empty_inputs));
    let mut extra_output = generic_plan(now_ms);
    extra_output.outputs.push(sample_output());
    plans.push(("outputs exceed the shape", extra_output));
    let mut extra_input = generic_plan(now_ms);
    extra_input.inputs.push(SppPlanInputV1::Wallet {
        commitment: [0x78; 32],
    });
    plans.push(("inputs exceed the shape", extra_input));
    let mut too_many_messages = generic_plan(now_ms);
    too_many_messages.messages = (0..9)
        .map(|_| SppMessageV1 {
            view_tag: [0x11; 32],
            data: Vec::new(),
        })
        .collect();
    plans.push(("message count", too_many_messages));
    let mut expired = generic_plan(now_ms);
    expired.expires_at_ms = now_ms.saturating_sub(1_000);
    plans.push(("expired plan", expired));
    let mut distant = generic_plan(now_ms);
    distant.expires_at_ms = now_ms + 400_000;
    plans.push(("expiry beyond the window", distant));
    let mut pool_target = generic_plan(now_ms);
    pool_target.program_id = Pubkey::new_from_array(SHIELDED_POOL_PROGRAM_ID).to_string();
    plans.push(("shielded pool as target", pool_target));
    let mut unsupported_shape = generic_plan(now_ms);
    unsupported_shape.shape = SppShapeV1 {
        inputs: 1,
        outputs: 5,
    };
    unsupported_shape.outputs = (0..5).map(|_| sample_output()).collect();
    plans.push(("unsupported shape", unsupported_shape));
    let mut oversized_message = generic_plan(now_ms);
    oversized_message.messages = vec![SppMessageV1 {
        view_tag: [0x11; 32],
        data: vec![0u8; 4_097],
    }];
    plans.push(("oversized message data", oversized_message));
    let mut oversized_memo = generic_plan(now_ms);
    oversized_memo.outputs[0].memo = vec![0u8; 4_097];
    plans.push(("oversized output memo", oversized_memo));
    let mut unhashed_data = generic_plan(now_ms);
    unhashed_data.outputs[0].data = vec![1];
    plans.push(("output data without a hash", unhashed_data));

    for (name, plan) in plans {
        let result = prepare_generic_spp(&request, &target, &plan, &keys).await;
        assert!(result.is_err(), "{name}");
    }
}

#[test]
fn asset_totals_accumulate_sort_and_fail_closed_on_overflow() {
    let a = Address::new_from_array([2; 32]);
    let b = Address::new_from_array([1; 32]);
    let mut totals = Vec::new();
    add_asset_amount(&mut totals, a, 5).expect("add");
    add_asset_amount(&mut totals, a, 7).expect("add");
    add_asset_amount(&mut totals, b, 1).expect("add");
    assert_eq!(totals, vec![(a, 12), (b, 1)]);
    sort_asset_totals(&mut totals);
    assert_eq!(totals, vec![(b, 1), (a, 12)]);

    let mut saturated = vec![(a, u128::MAX)];
    assert!(add_asset_amount(&mut saturated, a, 1).is_err());
}
