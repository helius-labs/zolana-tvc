import { signP256Prehash } from "../crypto/p256.js";
import devnetProverPolicy from "../devnet-prover-policy.json";
import { proverPolicyDigest } from "./digest.js";
import { encodeLowerHex } from "./hex.js";
import { p256SecretFromKeyFile } from "./key-file.js";
import type { ProverPolicy, SignedProverPolicy } from "./types.js";

/**
 * The devnet prover policy key the enclave is built with (`PROVER_POLICY_PUBLIC`
 * in `apps/privacy-wallet/src/operations/mod.rs`). The enclave seals a witness
 * only to a prover a policy signed by this key admits.
 */
export const DEVELOPMENT_PROVER_POLICY_PUBLIC_KEY =
  "0407c0a2e3a46927c42d257907b543e1f479f8e91a75ce15aeffb4f805f802bb91b177ab2472bca8161348221cd0f77a3d5c3f95893036ec6371771f2331d815fc";

/**
 * The devnet TEE prover deployment, signed by the devnet prover policy key and
 * valid until its `expiresAtMs`; `scripts/sign-prover-policy.mjs` writes it.
 */
export const DEVNET_PROVER_POLICY: SignedProverPolicy = Object.freeze(
  devnetProverPolicy as SignedProverPolicy,
);

/**
 * The prover policy secret from a key file (`{"private_key": hex}`), checked to
 * be the key the enclave expects. The caller wipes it after use.
 */
export function proverPolicySecret(
  keyJson: string,
  expectedPublicKey: string = DEVELOPMENT_PROVER_POLICY_PUBLIC_KEY,
): Uint8Array {
  return p256SecretFromKeyFile(keyJson, expectedPublicKey, {
    invalid: "InvalidProverPolicyKey",
    wrong: "WrongProverPolicyKey",
  });
}

/** `policy` signed as the 64-byte raw low-S P-256 signature over `proverPolicyDigest`. */
export function signProverPolicy(policy: ProverPolicy, secret: Uint8Array): SignedProverPolicy {
  return Object.freeze({
    policy,
    scheme: "p256-sha256",
    signature: encodeLowerHex(signP256Prehash(secret, proverPolicyDigest(policy))),
  });
}
