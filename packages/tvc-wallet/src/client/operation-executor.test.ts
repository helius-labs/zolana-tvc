import { readFileSync } from "node:fs";
import { p256 } from "@noble/curves/p256";
import { describe, expect, it, vi } from "vitest";
import { signP256Prehash } from "../crypto/p256.js";
import { qosDecrypt } from "../crypto/qos.js";
import { clientKeyIdFor } from "../protocol/digest.js";
import { decodeLowerHex, encodeLowerHex } from "../protocol/hex.js";
import type { OperationRequest, ServiceInfo, WalletDescriptor } from "../protocol/types.js";
import { executeOperationEnvelope, type OperationExecutionContext } from "./operation-executor.js";

function fixture() {
  const secret = new Uint8Array(32).fill(1);
  const publicKey = p256.getPublicKey(secret, false);
  const { descriptor } = JSON.parse(readFileSync(new URL(
    "../../../../crates/protocol/fixtures/descriptor-digest.json", import.meta.url,
  ), "utf8")) as { descriptor: WalletDescriptor };
  descriptor.allowed_clients = [{ client_public_key: encodeLowerHex(publicKey), allowed_operations: ["Decrypt"] }];
  const info = {
    version: 1, environment: "development", security_domain_id: "00".repeat(32),
    release_id: "test-é", manifest_digest: "11".repeat(32), executable_digest: "22".repeat(32),
    quorum_public_key: encodeLowerHex(publicKey) + encodeLowerHex(publicKey),
    quorum_key_id: "quorum-é", quorum_key_epoch: "1", ephemeral_public_key: "",
    supported_operations: ["Decrypt"], max_encrypted_request_bytes: "262144",
    max_encrypted_response_bytes: "262144", proof_type: "", boot_proof_lookup_key: "",
  } satisfies ServiceInfo;
  const sign = vi.fn(async ({ clientAuthDigest }: { clientAuthDigest: Uint8Array }) => signP256Prehash(secret, clientAuthDigest));
  const fetch = vi.fn(async (_url: unknown, _init?: RequestInit) => new Response("", { status: 503 }));
  const context: OperationExecutionContext = {
    endpoint: new URL("https://example.invalid"), info, transport: { fetch },
    operations: { walletDescriptor: descriptor, authorizer: { clientKeyId: clientKeyIdFor(publicKey), authorizeTvcRequest: sign } },
    acceptedManifestDigests: [info.manifest_digest], releasePolicyValidFromMs: 0n,
    releasePolicyExpiresAtMs: 9999999n, nowMs: () => 1000n,
    trustVerifier: { verifyOperationAppProof: async () => {}, verifyCustodyProofs: () => {} },
  };
  const item = {
    ciphertext: "ab".repeat(128), viewing_public_key: "02" + "11".repeat(32),
    transaction_viewing_public_key: "03" + "22".repeat(32), salt: "33".repeat(16),
    slot_index: "1", label: "Transfer" as const,
  };
  return { context, item, sign, fetch, secret };
}

describe("serialized operation request budget", () => {
  it("rejects 256 128-byte ciphertexts locally before authorization or fetch", async () => {
    const { context, item, sign, fetch } = fixture();
    await expect(executeOperationEnvelope(context, { type: "Decrypt", items: Array(256).fill(item) }))
      .rejects.toMatchObject({ code: "RequestTooLarge" });
    expect(sign).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
  });

  it("accepts the exact UTF-8 envelope limit and rejects one byte less", async () => {
    const { context, item, sign, fetch, secret } = fixture();
    const operation = { type: "Decrypt" as const, items: [item] };
    const send = () => executeOperationEnvelope(context, operation, { sealedSeed: "aa".repeat(128) });
    await expect(send()).rejects.toMatchObject({ code: "OperationUnavailable" });
    const body = fetch.mock.calls[0]?.[1]?.body as string;
    const request = JSON.parse(new TextDecoder().decode(qosDecrypt(secret,
      decodeLowerHex((JSON.parse(body) as { ciphertext: string }).ciphertext)))) as OperationRequest;
    expect(request.operation).toEqual(operation);
    const limit = new TextEncoder().encode(body).length;
    context.info.max_encrypted_request_bytes = String(limit);
    await expect(send()).rejects.toMatchObject({ code: "OperationUnavailable" });
    expect(fetch).toHaveBeenCalledTimes(2);
    context.info.max_encrypted_request_bytes = String(limit - 1);
    sign.mockClear();
    await expect(send()).rejects.toMatchObject({ code: "RequestTooLarge" });
    expect(sign).not.toHaveBeenCalled();
    expect(fetch).toHaveBeenCalledTimes(2);
  });
});
