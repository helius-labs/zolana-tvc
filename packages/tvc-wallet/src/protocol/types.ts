export type Environment = "development" | "production";

export type OperationKind = "Bootstrap" | "Decrypt" | "Derive" | "TransactionKeys" | "Prove";

export type HealthResponse = {
  status: "Healthy";
};

export type ServiceInfo = {
  version: number;
  environment: Environment;
  security_domain_id: string;
  release_id: string;
  manifest_digest: string;
  executable_digest: string;
  quorum_public_key: string;
  quorum_key_id: string;
  quorum_key_epoch: string;
  ephemeral_public_key: string;
  supported_operations: OperationKind[];
  max_encrypted_request_bytes: string;
  max_encrypted_response_bytes: string;
  proof_type: string;
  boot_proof_lookup_key: string;
};

export type ReleasePolicy = {
  version: 1;
  releaseId: string;
  environment: Environment;
  tvcApplicationId: string;
  securityDomainId: string;
  acceptedManifestDigests: readonly string[];
  acceptedExecutableDigests: readonly string[];
  quorumKeyId: string;
  quorumKeyEpoch: string;
  quorumPublicKey: string;
  allowedOperations: readonly OperationKind[];
  maxEncryptedRequestBytes: number;
  maxEncryptedResponseBytes: number;
  turnkeyTrustRootId: string;
  turnkeyProofSchemaVersions: readonly string[];
  validFromMs: string;
  expiresAtMs: string;
  revocationEpoch: string;
};

export type ReleaseAuthoritySignature = {
  keyId: string;
  scheme: "p256-sha256";
  signature: string;
};

export type SignedReleasePolicy = {
  policy: ReleasePolicy;
  authoritySetId: string;
  signatures: readonly ReleaseAuthoritySignature[];
};

export type ReleaseAuthorityKey = {
  keyId: string;
  publicKey: string;
};

export type PinnedReleaseAuthorities = {
  authoritySetId: string;
  threshold: number;
  keys: readonly ReleaseAuthorityKey[];
  /** Policies below the epoch are revoked. */
  minimumRevocationEpoch: string;
};

type ClientAuthorizationScheme = "p256-sha256";

export type ClientGrant = {
  client_public_key: string;
  allowed_operations: OperationKind[];
};

/**
 * Provisioned out of band. This package never manufactures or silently rotates
 * descriptor authority.
 */
export type WalletDescriptor = {
  version: 1;
  security_domain_id: string;
  environment: "development";
  turnkey_organization_id: string;
  turnkey_wallet_id: string;
  address: string;
  allowed_clients: ClientGrant[];
  provisioning_signature: string;
};

/** Which cipher a ciphertext was sealed under. */
export type DecryptLabel = "Transfer" | "RingDeposit";

/**
 * One ciphertext to open with the wallet's viewing key. The answer is the
 * cipher's output, which the caller decodes; the enclave interprets nothing.
 */
export type DecryptItem = {
  ciphertext: string;
  /** Which of the wallet's viewing keys opens it; the enclave holds one. */
  viewing_public_key: string;
  transaction_viewing_public_key: string;
  salt: string;
  /** Zero for a ring deposit, which carries one envelope. */
  slot_index: string;
  label: DecryptLabel;
};

/** One value the protocol derives from the nullifier secret. */
export type DeriveItem =
  | { kind: "Nullifier"; utxo_hash: string; blinding: string }
  | { kind: "MergeDummyNullifier"; first_nullifier: string; slot_index: string }
  | { kind: "MergeOutputBlinding"; first_nullifier: string };

/** One per-transaction viewing key, named by the viewing key and the transaction's first nullifier. */
export type TransactionKeyItem = {
  viewing_public_key: string;
  first_nullifier: string;
};

/**
 * The prover's request body as the Zolana SDK encodes it, with `null` in every
 * nullifier secret slot the enclave is to fill (`proverRequestBody` and
 * `mergeProverRequestBody` from `@heliuslabs/zolana/client`).
 */
export type ProverRequest = Readonly<Record<string, unknown>>;

export type BootstrapOperation = { type: "Bootstrap" };

export type DecryptOperation = { type: "Decrypt"; items: readonly DecryptItem[] };

export type DeriveOperation = { type: "Derive"; items: readonly DeriveItem[] };

export type TransactionKeysOperation = {
  type: "TransactionKeys";
  items: readonly TransactionKeyItem[];
};

export type ProveOperation = { type: "Prove"; request: ProverRequest };

export type Operation =
  | BootstrapOperation
  | DecryptOperation
  | DeriveOperation
  | TransactionKeysOperation
  | ProveOperation;

export type ClientAuthorization = {
  client_key_id: string;
  scheme: ClientAuthorizationScheme;
  signature: string;
};

export type OperationRequest = {
  version: 1;
  request_id: string;
  issued_at_ms: string;
  expires_at_ms: string;
  target_release_id: string;
  target_manifest_digest: string;
  target_executable_digest: string;
  quorum_key_id: string;
  quorum_key_epoch: string;
  wallet_descriptor: WalletDescriptor;
  sealed_wallet_state: string | null;
  client_response_public_key: string;
  operation: Operation;
  authorization: ClientAuthorization;
};

export type TurnkeyAppProof = {
  scheme: string;
  public_key: string;
  proof_payload: string;
  signature: string;
};

/** The sealed key state a bootstrap returns; presented on every later request. */
export type Checkpoint = {
  sealedWalletState: string;
};

export type BootstrapResult = {
  type: "Bootstrap";
  solana_address: string;
  shielded_owner_hash: string;
  shielded_nullifier_public_key: string;
  shielded_viewing_public_key: string;
  /** The seed sealed to the Quorum key. No secret appears elsewhere. */
  sealed_wallet_state: string;
  turnkey_activity_id: string;
  turnkey_app_proofs: TurnkeyAppProof[];
};

/** One plaintext per item, in request order. */
export type DecryptResult = {
  type: "Decrypt";
  plaintexts: readonly string[];
};

/** One value per item, in request order. */
export type DeriveResult = {
  type: "Derive";
  values: readonly string[];
};

/** One per-transaction viewing secret per item, in request order. */
export type TransactionKeysResult = {
  type: "TransactionKeys";
  secrets: readonly string[];
};

/** The prover's response, as it answered; `parseProof` from the SDK reads it. */
export type ProveResult = {
  type: "Prove";
  proof: unknown;
};

export type FailureStage = "Prover" | "TurnkeySigning";

export type FailureResult = {
  type: "Failure";
  operation: OperationKind;
  stage: FailureStage;
};

export type OperationResult =
  | BootstrapResult
  | DecryptResult
  | DeriveResult
  | TransactionKeysResult
  | ProveResult
  | FailureResult;

export const SERVICE_INFO_KEYS = [
  "version",
  "environment",
  "security_domain_id",
  "release_id",
  "manifest_digest",
  "executable_digest",
  "quorum_public_key",
  "quorum_key_id",
  "quorum_key_epoch",
  "ephemeral_public_key",
  "supported_operations",
  "max_encrypted_request_bytes",
  "max_encrypted_response_bytes",
  "proof_type",
  "boot_proof_lookup_key",
] as const;

export const HEALTH_KEYS = ["status"] as const;
