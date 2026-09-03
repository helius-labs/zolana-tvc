import { describe, expect, it } from "vitest";
import {
  CborError,
  decodeAwsNitroAttestationCbor,
  decodeCbor,
  encodeCoseSigStructure,
} from "./cbor.js";
import { decodeLowerHex, encodeLowerHex } from "../../protocol/hex.js";

function decodeHex(hex: string) {
  return decodeCbor(decodeLowerHex(hex));
}

describe("strict CBOR decoder", () => {
  it("decodes the deterministic subset an attestation document uses", () => {
    expect(decodeHex("00")).toBe(0);
    expect(decodeHex("17")).toBe(23);
    expect(decodeHex("1818")).toBe(24);
    expect(decodeHex("1903e8")).toBe(1000);
    expect(decodeHex("1b000001977420dc00")).toBe(1_750_000_000_000);
    expect(decodeHex("20")).toBe(-1);
    expect(decodeHex("f4")).toBe(false);
    expect(decodeHex("f5")).toBe(true);
    expect(decodeHex("f6")).toBe(null);
    expect(decodeHex("6449455446")).toBe("IETF");
    expect(encodeLowerHex(decodeHex("43010203") as Uint8Array)).toBe("010203");
    expect(decodeHex("83010203")).toEqual([1, 2, 3]);
  });

  it("decodes maps into a Map keyed by text or integer", () => {
    const value = decodeHex("a2616101010f") as Map<string | number, unknown>;
    expect(value).toBeInstanceOf(Map);
    expect(value.get("a")).toBe(1);
    expect(value.get(1)).toBe(15);
  });

  it("keeps a __proto__ key as inert data instead of reaching a prototype setter", () => {
    // a1 69 5f5f70726f746f5f5f a0  =>  {"__proto__": {}}
    const value = decodeHex("a1695f5f70726f746f5f5fa0") as Map<string, unknown>;
    expect(value.get("__proto__")).toBeInstanceOf(Map);
    expect(Object.getPrototypeOf(value)).toBe(Map.prototype);
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  });

  it("copies byte strings rather than viewing the input buffer", () => {
    const input = decodeLowerHex("43010203");
    const bytes = decodeCbor(input) as Uint8Array;
    input.fill(0xff);
    expect(encodeLowerHex(bytes)).toBe("010203");
  });

  it("rejects indefinite lengths", () => {
    expect(() => decodeHex("5f42010243030405ff")).toThrowError(CborError);
    expect(() => decodeHex("9f018202039f0405ffff")).toThrowError(CborError);
    expect(() => decodeHex("bf61610161629f0203ffff")).toThrowError(CborError);
  });

  it("accepts only the bounded indefinite root map emitted by AWS Nitro", () => {
    const value = decodeAwsNitroAttestationCbor(
      decodeLowerHex("bf696d6f64756c655f6964616d6470637273a10043010203ff"),
    ) as Map<string | number, unknown>;
    expect(value.get("module_id")).toBe("m");
    expect(value.get("pcrs")).toBeInstanceOf(Map);

    expect(() =>
      decodeAwsNitroAttestationCbor(decodeLowerHex("bf6161bf616201ffff")),
    ).toThrowError(/unsupported CBOR argument/);
    expect(() =>
      decodeAwsNitroAttestationCbor(decodeLowerHex("bf616101616102ff")),
    ).toThrowError(/duplicate/);
    expect(() =>
      decodeAwsNitroAttestationCbor(decodeLowerHex("bf6161ff")),
    ).toThrowError(/missing a value/);
    expect(() =>
      decodeAwsNitroAttestationCbor(
        Uint8Array.from([
          0xbf,
          ...Array.from({ length: 33 }, (_, index) =>
            index < 24 ? [index, 0] : [0x18, index, 0],
          ).flat(),
          0xff,
        ]),
      ),
    ).toThrowError(/too many entries/);
  });

  it("rejects non-shortest argument encodings", () => {
    expect(() => decodeHex("1817")).toThrowError(/non-minimal/);
    expect(() => decodeHex("190018")).toThrowError(/non-minimal/);
    expect(() => decodeHex("1a000003e8")).toThrowError(/non-minimal/);
    expect(() => decodeHex("1b00000000000003e8")).toThrowError(/non-minimal/);
  });

  it("rejects floats and unassigned simple values", () => {
    expect(() => decodeHex("f93c00")).toThrowError(CborError);
    expect(() => decodeHex("fa47c35000")).toThrowError(CborError);
    expect(() => decodeHex("fb3ff199999999999a")).toThrowError(CborError);
    expect(() => decodeHex("f7")).toThrowError(CborError);
  });

  it("rejects duplicate map keys and non-scalar keys", () => {
    expect(() => decodeHex("a2616101616102")).toThrowError(/duplicate/);
    expect(() => decodeHex("a18101 01".replace(/ /g, ""))).toThrowError(/map key/);
  });

  it("rejects trailing bytes, truncation, and unsupported tags", () => {
    expect(() => decodeHex("0000")).toThrowError(/trailing bytes/);
    expect(() => decodeHex("43 0102".replace(/ /g, ""))).toThrowError(/truncated/);
    expect(() => decodeHex("830102")).toThrowError(/truncated/);
    expect(() => decodeHex("c07818323031332d30332d32315432303a30343a30305a")).toThrowError(
      /unsupported CBOR tag/,
    );
  });

  it("unwraps the COSE_Sign1 tag only as the outermost item", () => {
    expect(decodeHex("d24101")).toEqual(decodeLowerHex("01"));
    // 81 d2 4101 => [18(h'01')]; a tag nested inside the payload is rejected.
    expect(() => decodeHex("81d24101")).toThrowError(/unsupported CBOR tag/);
  });

  it("rejects nesting past the depth limit", () => {
    const deep = "81".repeat(64) + "00";
    expect(() => decodeHex(deep)).toThrowError(/nesting too deep/);
  });

  it("rejects invalid UTF-8 in text strings", () => {
    expect(() => decodeHex("62c328")).toThrowError();
  });
});

describe("COSE Sig_structure encoding", () => {
  it("produces the canonical array the ES384 signature covers", () => {
    const encoded = encodeCoseSigStructure(
      decodeLowerHex("a10138"),
      new Uint8Array(0),
      decodeLowerHex("0102030405"),
    );
    // 84 | 6a "Signature1" | 43 a10138 | 40 | 45 0102030405
    expect(encodeLowerHex(encoded)).toBe(
      "846a5369676e61747572653143a101384045" + "0102030405",
    );
    expect(decodeCbor(encoded)).toEqual([
      "Signature1",
      decodeLowerHex("a10138"),
      new Uint8Array(0),
      decodeLowerHex("0102030405"),
    ]);
  });

  it("round-trips byte strings that need multi-byte length headers", () => {
    const payload = new Uint8Array(500).fill(0xab);
    const decoded = decodeCbor(
      encodeCoseSigStructure(new Uint8Array(0), new Uint8Array(0), payload),
    ) as unknown[];
    expect(decoded[3]).toEqual(payload);
  });
});
