import { describe, expect, it } from "vitest";

import { isSolanaAddress, isSolanaSignature } from "./persisted-state.js";

const ADDRESS = "FpGCh7CJuKcphxuzcFacq7uNfvYkJpCXdLCAH5cpxhRE";
const SIGNATURE =
  "66ytoWsAdgaWtEfs9mZW6Hi8HFd7q5FvjfCEfXpqDFgtmSDPxm5hEJXH1Azsc1stFn4BH83HfabAxnhxD2GuVKQ3";

describe("Solana persisted identifiers", () => {
  it("distinguishes 32-byte addresses from 64-byte signatures", () => {
    expect(isSolanaAddress(ADDRESS)).toBe(true);
    expect(isSolanaAddress(SIGNATURE)).toBe(false);
    expect(isSolanaSignature(SIGNATURE)).toBe(true);
    expect(isSolanaSignature(ADDRESS)).toBe(false);
  });
});
