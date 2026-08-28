import { describe, expect, it } from "vitest";
import { authorizedRequestMessage } from "./authorizer.js";
import { clientAuthMessage, requestDigest } from "../protocol/digest.js";
import type { AuthorizeTvcRequestInput } from "../client/operation-executor.js";
import type { OperationRequestV1 } from "../protocol/types.js";

const CLIENT_KEY_ID = "tvc-browser-p256-" + "11".repeat(16);

function request(): OperationRequestV1 {
  return {
    version: 1,
    request_id: "aa".repeat(32),
    issued_at_ms: "1750000000000",
    expires_at_ms: "1750000300000",
    target_release_id: "release-1",
    target_manifest_digest: "11".repeat(32),
    target_executable_digest: "22".repeat(32),
    quorum_key_id: "quorum-1",
    quorum_key_epoch: "1",
    wallet_descriptor: { wallet_id: "wallet-1" } as unknown as OperationRequestV1["wallet_descriptor"],
    sealed_wallet_state: null,
    expected_state_version: null,
    expected_state_digest: null,
    client_response_public_key: "04".repeat(65),
    operation: { type: "BootstrapKeyholder" },
    authorization: { client_key_id: CLIENT_KEY_ID, scheme: "p256-sha256", signature: "" },
  };
}

function input(overrides: Partial<AuthorizeTvcRequestInput> = {}): AuthorizeTvcRequestInput {
  const value = request();
  return {
    operation: value.operation,
    request: value,
    clientAuthDigest: new Uint8Array(32),
    clientAuthMessage: clientAuthMessage(requestDigest(value)),
    ...overrides,
  };
}

describe("browser authorizer request guard", () => {
  it("returns the message rederived from the request it was shown", () => {
    const value = input();
    expect(authorizedRequestMessage(value, CLIENT_KEY_ID)).toEqual(
      clientAuthMessage(requestDigest(value.request)),
    );
  });

  it("refuses to sign bytes that are not this request's authorization message", () => {
    // A signing oracle would sign whatever the caller handed it; the authorizer
    // must reject anything it cannot rederive from the disclosed request.
    expect(() =>
      authorizedRequestMessage(
        input({ clientAuthMessage: new Uint8Array(64).fill(9) }),
        CLIENT_KEY_ID,
      ),
    ).toThrowError(/OperationNotAllowed/);
    expect(() =>
      authorizedRequestMessage(input({ clientAuthMessage: new Uint8Array(0) }), CLIENT_KEY_ID),
    ).toThrowError(/OperationNotAllowed/);
  });

  it("refuses a message that belongs to a different request", () => {
    const other = request();
    other.operation = { type: "DeriveViewTags" };
    expect(() =>
      authorizedRequestMessage(
        input({ clientAuthMessage: clientAuthMessage(requestDigest(other)) }),
        CLIENT_KEY_ID,
      ),
    ).toThrowError(/OperationNotAllowed/);
  });

  it("refuses a request authorized under another client key id", () => {
    expect(() => authorizedRequestMessage(input(), "tvc-browser-p256-" + "22".repeat(16))).toThrowError(
      /OperationNotAllowed/,
    );
  });
});
