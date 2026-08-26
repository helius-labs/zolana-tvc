import { p256 } from "@noble/curves/p256";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { parseQosP256Public, qosDecrypt, qosEncrypt } from "../crypto/qos.js";
import { signP256Message, signP256Prehash } from "../crypto/p256.js";
import { clientAuthDigest, requestDigest, resultDigest } from "../protocol/digest.js";
import { decodeLowerHex, encodeLowerHex } from "../protocol/hex.js";
import { TvcError } from "../protocol/error.js";
import { canonicalizeJsonValue } from "../protocol/jcs.js";
import type {
  OperationRequestV1,
  PinnedReleaseAuthoritiesV1,
  ReleasePolicyV1,
  ServiceInfoV1,
  SignedReleasePolicyV1,
  WalletDescriptorV1,
} from "../protocol/types.js";
import { policySigningDigest } from "../verify/release-policy.js";
import { createTvcWalletClient } from "./index.js";
import { readBoundedText } from "./http.js";
import {
  authorizeDefaultRingTransferOperation,
  defaultRingSolWithdrawalIntentDigest,
  defaultRingTransferIntentDigest,
  verifyDefaultRingAuthorizationResult,
} from "./operations.js";

const verifyBootProofMock = vi.hoisted(() => vi.fn());

vi.mock("../verify/index.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../verify/index.js")>()),
  verifyBootProof: verifyBootProofMock,
}));

function secret(label: string): Uint8Array {
  return sha256(new TextEncoder().encode(label));
}

function qosPublic(encryptionSecret: Uint8Array, signingSecret: Uint8Array) {
  return encodeLowerHex(
    Uint8Array.from([
      ...p256.getPublicKey(encryptionSecret, false),
      ...p256.getPublicKey(signingSecret, false),
    ]),
  );
}

function encodeBase58(bytes: Uint8Array): string {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let leadingZeroes = 0;
  while (leadingZeroes < bytes.length && bytes[leadingZeroes] === 0) {
    leadingZeroes += 1;
  }
  if (leadingZeroes === bytes.length) return "1".repeat(leadingZeroes);
  const digits = [0];
  for (let index = leadingZeroes; index < bytes.length; index += 1) {
    let carry = bytes[index] ?? 0;
    for (let digit = 0; digit < digits.length; digit += 1) {
      carry += (digits[digit] ?? 0) * 256;
      digits[digit] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  return (
    "1".repeat(leadingZeroes) +
    digits
      .reverse()
      .map((digit) => alphabet[digit])
      .join("")
  );
}

function authorizationResultFixture() {
  const secretKey = secret("default-ring-solana-signer");
  const publicKey = ed25519.getPublicKey(secretKey);
  const message = new Uint8Array([1, 0, 0, 1, ...new Uint8Array(32).fill(9)]);
  const signature = ed25519.sign(message, secretKey);
  const unsignedTransaction = Uint8Array.from([1, ...new Uint8Array(64), ...message]);
  const signedTransaction = Uint8Array.from([1, ...signature, ...message]);
  const result = {
    type: "AuthorizeDefaultRingTransfer" as const,
    signed_transaction: encodeLowerHex(signedTransaction),
    transaction_signature: encodeBase58(signature),
    intent_digest: "77".repeat(32),
    turnkey_activity_id: "activity-transfer",
    turnkey_app_proofs: [],
    evidence_classification: "CryptographicallyValidButUnbound" as const,
  };
  return { publicKey, result, signedTransaction, unsignedTransaction };
}

describe("lightweight typed wallet operations", () => {
  beforeEach(() => verifyBootProofMock.mockReset().mockResolvedValue(undefined));

  it("derives the intent digest from the exact bytes it authorizes", () => {
    const intent = {
      walletId: "wallet-1",
      solanaAddress: "payer",
      recipient: "recipient",
      asset: { type: "Sol" as const },
      amount: 10n,
      unsignedTransaction: new Uint8Array([1, 2, 3]),
    };
    const operation = authorizeDefaultRingTransferOperation({ kind: "transfer", intent });
    expect(operation).toEqual({
      type: "AuthorizeDefaultRingTransfer",
      intent_digest: encodeLowerHex(defaultRingTransferIntentDigest(intent)),
      unsigned_transaction: "010203",
    });

    // Changing the bytes must change the digest the request carries; the two
    // can no longer be supplied independently.
    const other = authorizeDefaultRingTransferOperation({
      kind: "transfer",
      intent: { ...intent, unsignedTransaction: new Uint8Array([1, 2, 4]) },
    });
    expect(other.intent_digest).not.toBe(operation.intent_digest);

    // The same wallet, recipient, amount, and bytes under the withdrawal
    // domain must not collide with the transfer digest.
    expect(
      authorizeDefaultRingTransferOperation({
        kind: "solWithdrawal",
        intent: {
          walletId: intent.walletId,
          solanaAddress: intent.solanaAddress,
          recipient: intent.recipient,
          amount: intent.amount,
          unsignedTransaction: intent.unsignedTransaction,
        },
      }).intent_digest,
    ).not.toBe(operation.intent_digest);
  });

  it("rejects an unbounded or empty default-ring transaction", () => {
    const intent = {
      walletId: "wallet-1",
      solanaAddress: "payer",
      recipient: "recipient",
      asset: { type: "Sol" as const },
      amount: 10n,
      unsignedTransaction: new Uint8Array(1_233),
    };
    expect(() =>
      authorizeDefaultRingTransferOperation({ kind: "transfer", intent }),
    ).toThrowError("InvalidTransferIntent");
    expect(() =>
      authorizeDefaultRingTransferOperation({
        kind: "transfer",
        intent: { ...intent, unsignedTransaction: new Uint8Array(0) },
      }),
    ).toThrowError("InvalidTransferIntent");
    expect(() =>
      authorizeDefaultRingTransferOperation({
        kind: "transfer",
        intent: { ...intent, amount: 0n, unsignedTransaction: new Uint8Array([1]) },
      }),
    ).toThrowError("InvalidTransferIntent");
  });

  it("binds the semantic transfer intent to the exact transaction bytes", () => {
    const input = {
      walletId: "wallet-1",
      solanaAddress: "payer",
      recipient: "recipient",
      asset: { type: "Sol" as const },
      amount: 10n,
      unsignedTransaction: new Uint8Array([1, 2, 3]),
    };
    const digest = defaultRingTransferIntentDigest(input);
    expect(digest).toHaveLength(32);
    expect(
      encodeLowerHex(
        defaultRingTransferIntentDigest({
          ...input,
          unsignedTransaction: new Uint8Array([1, 2, 4]),
        }),
      ),
    ).not.toBe(encodeLowerHex(digest));
    expect(encodeLowerHex(defaultRingTransferIntentDigest({ ...input, amount: 11n }))).not.toBe(
      encodeLowerHex(digest),
    );
  });

  it("domain-separates a SOL withdrawal from a private transfer", () => {
    const common = {
      walletId: "wallet-1",
      solanaAddress: "payer",
      recipient: "recipient",
      amount: 10n,
      unsignedTransaction: new Uint8Array([1, 2, 3]),
    };
    const withdrawal = defaultRingSolWithdrawalIntentDigest(common);
    const transfer = defaultRingTransferIntentDigest({
      ...common,
      asset: { type: "Sol" },
    });
    expect(withdrawal).toHaveLength(32);
    expect(encodeLowerHex(withdrawal)).not.toBe(encodeLowerHex(transfer));
    expect(
      encodeLowerHex(defaultRingSolWithdrawalIntentDigest({ ...common, amount: 11n })),
    ).not.toBe(encodeLowerHex(withdrawal));
  });

  it("independently verifies the exact signed non-versioned transaction", () => {
    const fixture = authorizationResultFixture();
    expect(() =>
      verifyDefaultRingAuthorizationResult({
        unsignedTransaction: fixture.unsignedTransaction,
        result: fixture.result,
        expectedEd25519PublicKey: fixture.publicKey,
      }),
    ).not.toThrow();
  });

  it("rejects a changed message, signature, or reported transaction id", () => {
    const fixture = authorizationResultFixture();
    const changedMessage = fixture.signedTransaction.slice();
    changedMessage.set([(changedMessage.at(-1) ?? 0) ^ 1], changedMessage.length - 1);
    expect(() =>
      verifyDefaultRingAuthorizationResult({
        unsignedTransaction: fixture.unsignedTransaction,
        result: {
          ...fixture.result,
          signed_transaction: encodeLowerHex(changedMessage),
        },
        expectedEd25519PublicKey: fixture.publicKey,
      }),
    ).toThrowError("ReleaseBindingMismatch");

    const changedSignature = fixture.signedTransaction.slice();
    changedSignature.set([(changedSignature.at(1) ?? 0) ^ 1], 1);
    expect(() =>
      verifyDefaultRingAuthorizationResult({
        unsignedTransaction: fixture.unsignedTransaction,
        result: {
          ...fixture.result,
          signed_transaction: encodeLowerHex(changedSignature),
        },
        expectedEd25519PublicKey: fixture.publicKey,
      }),
    ).toThrowError("ReleaseBindingMismatch");

    expect(() =>
      verifyDefaultRingAuthorizationResult({
        unsignedTransaction: fixture.unsignedTransaction,
        result: { ...fixture.result, transaction_signature: "wrong" },
        expectedEd25519PublicKey: fixture.publicKey,
      }),
    ).toThrowError("ReleaseBindingMismatch");
  });

  it("authorizes, encrypts, verifies, and decrypts client bootstrap", async () => {
    const quorumEncryptionSecret = secret("ops-quorum-encryption");
    const quorumSigningSecret = secret("ops-quorum-signing");
    const ephemeralEncryptionSecret = secret("ops-ephemeral-encryption");
    const ephemeralSigningSecret = secret("ops-ephemeral-signing");
    const turnkeyProofEncryptionSecret = secret("ops-tk-proof-encryption");
    const turnkeyProofSigningSecret = secret("ops-tk-proof-signing");
    const clientSecret = secret("ops-client");
    const authoritySecret = secret("ops-authority");
    const quorumPublicKey = qosPublic(quorumEncryptionSecret, quorumSigningSecret);
    const ephemeralPublicKey = qosPublic(ephemeralEncryptionSecret, ephemeralSigningSecret);
    const manifestDigest = "11".repeat(32);
    const executableDigest = "22".repeat(32);
    const securityDomainId = "33".repeat(32);

    const policy: ReleasePolicyV1 = {
      version: 1,
      releaseId: "typed-ops-poc",
      environment: "development",
      tvcApplicationId: "wallet-dev",
      securityDomainId,
      acceptedManifestDigests: [manifestDigest],
      acceptedExecutableDigests: [executableDigest],
      quorumKeyId: "quorum-typed-ops",
      quorumKeyEpoch: "1",
      quorumPublicKey,
      allowedOperations: ["BootstrapClientEd25519", "AuthorizeDefaultRingTransfer"],
      maxEncryptedRequestBytes: 262_144,
      maxEncryptedResponseBytes: 262_144,
      turnkeyTrustRootId: "turnkey-dev",
      turnkeyProofSchemaVersions: ["v1"],
      turnkeyVerifierVersion: "ts-reference-poc",
      validFromMs: "1700000000000",
      expiresAtMs: "1800000000000",
      revocationEpoch: "0",
    };
    const releasePolicy: SignedReleasePolicyV1 = {
      policy,
      authoritySetId: "typed-ops-authorities",
      signatures: [
        {
          keyId: "typed-ops-authority",
          scheme: "p256-sha256",
          signature: encodeLowerHex(signP256Prehash(authoritySecret, policySigningDigest(policy))),
        },
      ],
    };
    const releaseAuthorities: PinnedReleaseAuthoritiesV1 = {
      authoritySetId: "typed-ops-authorities",
      threshold: 1,
      keys: [
        {
          keyId: "typed-ops-authority",
          publicKey: encodeLowerHex(p256.getPublicKey(authoritySecret, false)),
        },
      ],
    };
    const info: ServiceInfoV1 = {
      version: 1,
      environment: "development",
      security_domain_id: securityDomainId,
      release_id: policy.releaseId,
      manifest_digest: manifestDigest,
      executable_digest: executableDigest,
      quorum_public_key: quorumPublicKey,
      quorum_key_id: policy.quorumKeyId,
      quorum_key_epoch: policy.quorumKeyEpoch,
      ephemeral_public_key: ephemeralPublicKey,
      supported_operations: [...policy.allowedOperations],
      max_encrypted_request_bytes: "262144",
      max_encrypted_response_bytes: "262144",
      proof_type: "zolana.tvc.wallet_operation.v1",
      boot_proof_lookup_key: ephemeralPublicKey,
    };
    const descriptor: WalletDescriptorV1 = {
      version: 1,
      wallet_id: "typed-wallet",
      security_domain_id: securityDomainId,
      turnkey_parent_organization_id: "parent-org",
      turnkey_organization_id: "wallet-org",
      turnkey_signing_target: {
        type: "HdWalletAccount",
        turnkey_wallet_id: "turnkey-wallet",
        wallet_account_id: "turnkey-account",
        address: "DevnetAddress",
        derivation_path: "m/44'/501'/0'/0'",
      },
      turnkey_service_user_id: "service-user",
      turnkey_api_key_id: "api-key",
      expected_ed25519_public_key: "55".repeat(32),
      allowed_clients: [
        {
          client_key_id: "browser-client",
          scheme: "p256-sha256",
          client_public_key: encodeLowerHex(p256.getPublicKey(clientSecret, false)),
          allowed_operations: [...policy.allowedOperations],
          may_rotate_descriptor: false,
        },
      ],
      policy_version: "1",
      previous_descriptor_digest: null,
      environment: "development",
      provisioning_key_id: "provisioner",
      owner_authorization_key: null,
      recovery_binding: null,
      provisioning_signature: "66".repeat(64),
      owner_authorization: null,
      prior_client_authorization: null,
    };
    const authorizeTvcRequest = vi.fn(
      async ({ clientAuthDigest: digest }: { clientAuthDigest: Uint8Array }) =>
        signP256Prehash(clientSecret, digest),
    );
    const turnkeyProofPayload = canonicalizeJsonValue({
      type: "APP_PROOF_TYPE_POLICY_OUTCOME",
    });
    const turnkeyProofPublic = qosPublic(turnkeyProofEncryptionSecret, turnkeyProofSigningSecret);

    const transport = {
      fetch: async (url: URL, init?: RequestInit): Promise<Response> => {
        if (url.pathname === "/api/tvc/v1/info") {
          return new Response(canonicalizeJsonValue(info), { status: 200 });
        }
        if (url.pathname === "/api/tvc/v1/ping") {
          const outer = JSON.parse(String(init?.body)) as {
            encrypted_challenge: string;
          };
          const challenge = qosDecrypt(
            quorumEncryptionSecret,
            decodeLowerHex(outer.encrypted_challenge),
          );
          const payload = new TextDecoder().decode(challenge);
          return new Response(
            canonicalizeJsonValue({
              version: 1,
              tvc_app_proof: {
                scheme: "SIGNATURE_SCHEME_EPHEMERAL_KEY_P256",
                public_key: ephemeralPublicKey,
                proof_payload: payload,
                signature: encodeLowerHex(signP256Message(ephemeralSigningSecret, challenge)),
              },
            }),
            { status: 200 },
          );
        }

        const outer = JSON.parse(String(init?.body)) as { ciphertext: string };
        const request = JSON.parse(
          new TextDecoder().decode(
            qosDecrypt(quorumEncryptionSecret, decodeLowerHex(outer.ciphertext)),
          ),
        ) as OperationRequestV1;
        expect(request.operation).toEqual({ type: "BootstrapClientEd25519" });
        const digest = clientAuthDigest(requestDigest(request));
        expect(
          p256.verify(
            decodeLowerHex(request.authorization.signature),
            digest,
            p256.getPublicKey(clientSecret, false),
            { prehash: false },
          ),
        ).toBe(true);

        const result = canonicalizeJsonValue({
          type: "BootstrapClientEd25519",
          solana_address: "DevnetAddress",
          shielded_owner_hash: "77".repeat(32),
          shielded_nullifier_public_key: "88".repeat(32),
          shielded_viewing_public_key: `02${"99".repeat(32)}`,
          derivation_seed: "aa".repeat(64),
          derivation_suite: "zolana-ed25519-role-expansion-v1",
          turnkey_activity_id: "activity-bootstrap",
          turnkey_app_proofs: [
            {
              scheme: "SIGNATURE_SCHEME_EPHEMERAL_KEY_P256",
              public_key: turnkeyProofPublic,
              proof_payload: turnkeyProofPayload,
              signature: encodeLowerHex(
                signP256Message(
                  turnkeyProofSigningSecret,
                  new TextEncoder().encode(turnkeyProofPayload),
                ),
              ),
            },
          ],
          evidence_classification: "CryptographicallyValidButUnbound",
        });
        const responsePublic = parseQosP256Public(
          decodeLowerHex(request.client_response_public_key),
        );
        const encryptedResult = qosEncrypt(
          responsePublic.encryption,
          new TextEncoder().encode(result),
        );
        const proofPayload = canonicalizeJsonValue({
          type: "zolana.tvc.wallet_operation.v1",
          version: 1,
          request_id: request.request_id,
          request_digest: encodeLowerHex(requestDigest(request)),
          result_digest: encodeLowerHex(resultDigest(encryptedResult)),
          operation: "BootstrapClientEd25519",
          state_digest: "00".repeat(32),
        });
        return new Response(
          canonicalizeJsonValue({
            version: 1,
            request_id: request.request_id,
            encrypted_result: encodeLowerHex(encryptedResult),
            tvc_app_proof: {
              scheme: "SIGNATURE_SCHEME_EPHEMERAL_KEY_P256",
              public_key: ephemeralPublicKey,
              proof_payload: proofPayload,
              signature: encodeLowerHex(
                signP256Message(ephemeralSigningSecret, new TextEncoder().encode(proofPayload)),
              ),
            },
          }),
          { status: 200 },
        );
      },
    };

    let nowMs = 1_750_000_000_000n;
    const client = createTvcWalletClient({
      endpoint: new URL("https://tvc.example.invalid/api/tvc/"),
      releasePolicy,
      releaseAuthorities,
      qosIdentityPcrs: {
        0: "aa".repeat(48),
        1: "bb".repeat(48),
        2: "cc".repeat(48),
        3: "dd".repeat(48),
      },
      resolveBootProof: vi.fn().mockResolvedValue({}),
      nowMs: () => nowMs,
      transport,
      operations: {
        walletDescriptor: descriptor,
        authorizer: {
          clientKeyId: "browser-client",
          authorizeTvcRequest,
        },
      },
    });
    const connection = await client.connectAndVerify();
    const result = await client.bootstrapClientEd25519(connection);

    expect(result).toMatchObject({
      type: "BootstrapClientEd25519",
      derivation_suite: "zolana-ed25519-role-expansion-v1",
    });
    expect(authorizeTvcRequest).toHaveBeenCalledWith(
      expect.objectContaining({
        operation: { type: "BootstrapClientEd25519" },
        request: expect.objectContaining({
          sealed_wallet_state: null,
          authorization: expect.objectContaining({ signature: "" }),
        }),
      }),
    );
    expect("signTransaction" in client).toBe(false);
    expect("signMessage" in client).toBe(false);

    // A connection verified near policy expiry must not become a permanent
    // capability. Every newly authorized operation rechecks the live clock.
    nowMs = 1_800_000_000_001n;
    await expect(client.bootstrapClientEd25519(connection)).rejects.toThrowError(
      "ExpiredRequest",
    );
    expect(authorizeTvcRequest).toHaveBeenCalledTimes(1);
  });

  it("stops reading an oversized response instead of buffering it", async () => {
    // Streams far more than the ceiling, counting what the client actually
    // pulls. A client that buffered first would drain all 4096 chunks.
    let pulled = 0;
    const chunk = new Uint8Array(64 * 1024).fill(0x61);
    const stream = new ReadableStream<Uint8Array>({
      pull(controller) {
        pulled += 1;
        if (pulled > 4_096) {
          controller.close();
          return;
        }
        controller.enqueue(chunk);
      },
    });

    await expect(
      readBoundedText(new Response(stream, { status: 200 }), 589_824n),
    ).rejects.toThrowError("ResponseTooLarge");
    // 589_824-byte ceiling over 65_536-byte chunks: ~10 pulls, not 4096.
    expect(pulled).toBeLessThan(16);
  });

  it("returns the whole body when it fits inside the ceiling", async () => {
    expect(await readBoundedText(new Response("hello"), 64n)).toBe("hello");
    expect(await readBoundedText(new Response(null), 64n)).toBe("");
    // Exactly at the ceiling is accepted; one byte past it is not.
    expect(await readBoundedText(new Response("abcde"), 5n)).toBe("abcde");
    await expect(readBoundedText(new Response("abcdef"), 5n)).rejects.toThrowError(
      "ResponseTooLarge",
    );
  });

  it("rejects malformed UTF-8 as a protocol error, not a raw TypeError", async () => {
    // Response.text() would silently substitute U+FFFD here; the wire format is
    // canonical JSON, so the client must fail closed with a TvcError instead.
    const invalid = await readBoundedText(
      new Response(new Uint8Array([0xff, 0xfe])),
      64n,
    ).catch((error: unknown) => error);
    expect(invalid).toBeInstanceOf(TvcError);
    expect((invalid as TvcError).code).toBe("InvalidCanonicalJson");
  });

  it("rejects a ceiling that is not a usable byte count", async () => {
    await expect(readBoundedText(new Response("x"), 0n)).rejects.toThrowError("ResponseTooLarge");
    await expect(readBoundedText(new Response("x"), -1n)).rejects.toThrowError("ResponseTooLarge");
    await expect(
      readBoundedText(new Response("x"), BigInt(Number.MAX_SAFE_INTEGER) + 1n),
    ).rejects.toThrowError("ResponseTooLarge");
  });

  it("decodes multi-byte UTF-8 split across chunk boundaries", async () => {
    const bytes = new TextEncoder().encode("é€𝄞");
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        for (const byte of bytes) controller.enqueue(Uint8Array.of(byte));
        controller.close();
      },
    });
    expect(await readBoundedText(new Response(stream), 64n)).toBe("é€𝄞");
  });
});
