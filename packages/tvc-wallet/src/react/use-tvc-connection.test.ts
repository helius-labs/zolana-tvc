import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { configsEqual } from "./use-tvc-connection.js";

function readFixture(name: string): Record<string, unknown> {
  return JSON.parse(
    readFileSync(
      join(dirname(fileURLToPath(import.meta.url)), "../../../../crates/protocol/fixtures", name),
      "utf8",
    ),
  ) as Record<string, unknown>;
}

// A real caller holds these across renders: the device authorizer comes from
// IndexedDB once, and the transport and Boot Proof resolver come from an
// existing Turnkey session. Only the plain wrappers are re-allocated per render.
const AUTHORIZER = {
  clientKeyId: "client-1",
  authorizeTvcRequest: async () => new Uint8Array(64),
};
const RESOLVE_BOOT_PROOF = async () => ({});
const TRANSPORT = { fetch: async () => new Response("") };

/** Mirrors the shape a caller actually hands the provider. */
function realisticConfig() {
  const policy = readFixture("signed-release-policy.json");
  const authorizer = AUTHORIZER;
  const resolveBootProof = RESOLVE_BOOT_PROOF;
  const transport = TRANSPORT;
  return {
    endpoint: new URL("https://tvc.example.invalid/api/"),
    releasePolicy: policy.signed,
    releaseAuthorities: policy.authorities,
    qosIdentityPcrs: { 0: "00", 1: "11", 2: "22", 3: "33" },
    resolveBootProof,
    nowMs: 1_750_000_000_000n,
    transport,
    operations: {
      walletDescriptor: readFixture("descriptor-digest.json").descriptor,
      authorizer,
    },
  };
}

describe("provider config equality", () => {
  it("treats a re-allocated config with identical contents as unchanged", () => {
    const endpoint = "https://tvc.example.invalid/api/";
    const authorizer = { clientKeyId: "client-1", authorizeTvcRequest: async () => new Uint8Array() };
    const build = () => ({
      endpoint: new URL(endpoint),
      releasePolicy: { policy: { releaseId: "r1", acceptedManifestDigests: ["aa"] }, signatures: [] },
      qosIdentityPcrs: { 0: "00", 1: "11", 2: "22", 3: "33" },
      operations: {
        walletDescriptor: { turnkey_wallet_id: "w1", allowed_clients: [] },
        authorizer,
      },
    });
    expect(configsEqual(build(), build())).toBe(true);
  });

  it("sees through inline literals nested below the first level", () => {
    const authorizer = { clientKeyId: "client-1" };
    expect(
      configsEqual(
        { operations: { walletDescriptor: { turnkey_wallet_id: "w1" }, authorizer } },
        { operations: { walletDescriptor: { turnkey_wallet_id: "w1" }, authorizer } },
      ),
    ).toBe(true);
  });

  it("reports a change when any nested value differs", () => {
    expect(
      configsEqual(
        { operations: { walletDescriptor: { turnkey_wallet_id: "w1" } } },
        { operations: { walletDescriptor: { turnkey_wallet_id: "w2" } } },
      ),
    ).toBe(false);
    expect(configsEqual({ a: { b: [1, 2] } }, { a: { b: [1, 3] } })).toBe(false);
    expect(configsEqual({ a: { b: [1, 2] } }, { a: { b: [1] } })).toBe(false);
  });

  it("compares endpoints by href and detects a redirected endpoint", () => {
    expect(
      configsEqual(
        { endpoint: new URL("https://a.invalid/api/") },
        { endpoint: new URL("https://a.invalid/api/") },
      ),
    ).toBe(true);
    expect(
      configsEqual(
        { endpoint: new URL("https://a.invalid/api/") },
        { endpoint: new URL("https://evil.invalid/api/") },
      ),
    ).toBe(false);
  });

  it("treats a different authorizer, transport, or resolver as a different client", () => {
    // Behaviourally identical but distinct instances must still rebuild: the
    // signing authority is the object, not its shape.
    expect(
      configsEqual(
        { operations: { authorizer: { clientKeyId: "c", sign: () => 1 } } },
        { operations: { authorizer: { clientKeyId: "c", sign: () => 1 } } },
      ),
    ).toBe(false);
    const fetchFn = async () => new Response("");
    expect(configsEqual({ transport: { fetch: fetchFn } }, { transport: { fetch: fetchFn } })).toBe(
      true,
    );
  });

  it("does not treat a differing key set as equal", () => {
    expect(configsEqual({ a: 1 }, { b: 1 })).toBe(false);
    expect(configsEqual({ a: 1 }, { a: 1, b: 2 })).toBe(false);
    expect(configsEqual({ a: undefined }, {})).toBe(false);
  });

  it("compares class instances and typed arrays by identity", () => {
    const bytes = new Uint8Array([1, 2, 3]);
    expect(configsEqual({ bytes }, { bytes })).toBe(true);
    expect(configsEqual({ bytes }, { bytes: new Uint8Array([1, 2, 3]) })).toBe(false);
    expect(configsEqual({ map: new Map() }, { map: new Map() })).toBe(false);
  });

  it("rebuilds rather than recursing when a config nests past the bound", () => {
    const deep = (levels: number) => {
      let value: Record<string, unknown> = { end: true };
      for (let index = 0; index < levels; index += 1) value = { next: value };
      return value;
    };
    expect(configsEqual(deep(4), deep(4))).toBe(true);
    expect(configsEqual(deep(40), deep(40))).toBe(false);
  });

  it("terminates on a cyclic config instead of overflowing the stack", () => {
    const left: Record<string, unknown> = {};
    const right: Record<string, unknown> = {};
    left.self = left;
    right.self = right;
    expect(configsEqual(left, right)).toBe(false);
  });

  // Guards the depth bound: this fails the moment a descriptor or policy schema
  // change nests deeper than MAX_CONFIG_DEPTH, which would otherwise silently
  // reinstate the per-render client rebuild.
  it("holds a full production-shaped config stable across re-allocation", () => {
    expect(configsEqual(realisticConfig(), realisticConfig())).toBe(true);
  });

  it("still reports a change deep inside a production-shaped config", () => {
    const left = realisticConfig();
    const right = realisticConfig();
    (right.operations.walletDescriptor as Record<string, unknown>).turnkey_wallet_id =
      "other-wallet";
    expect(configsEqual(left, right)).toBe(false);
  });

  it("keeps bigint and null fields comparable by value", () => {
    expect(configsEqual({ nowMs: 1n, x: null }, { nowMs: 1n, x: null })).toBe(true);
    expect(configsEqual({ nowMs: 1n }, { nowMs: 2n })).toBe(false);
  });
});
