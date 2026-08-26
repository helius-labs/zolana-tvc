// Strict CBOR for AWS Nitro COSE_Sign1 attestation documents.
//
// This is deliberately not a general CBOR implementation. It accepts only the
// deterministic subset (RFC 8949 section 4.2) that NSM emits, because the bytes
// are attacker-controlled and are parsed *before* any signature is verified:
//
//   - definite lengths only; indefinite-length items are rejected;
//   - shortest-form argument encoding only, so a document has one encoding;
//   - no floats, no simple values beyond false/true/null;
//   - byte strings are copied, never returned as views into the input buffer;
//   - maps become `Map`, so a `"__proto__"` key cannot reach a prototype setter;
//   - duplicate map keys are rejected;
//   - nesting is depth-limited and trailing bytes are rejected.

const MAJOR_UNSIGNED = 0;
const MAJOR_NEGATIVE = 1;
const MAJOR_BYTES = 2;
const MAJOR_TEXT = 3;
const MAJOR_ARRAY = 4;
const MAJOR_MAP = 5;
const MAJOR_TAG = 6;
const MAJOR_SIMPLE = 7;

const COSE_SIGN1_TAG = 18;
const MAX_DEPTH = 16;

export type CborValue =
  | null
  | boolean
  | number
  | Uint8Array
  | string
  | CborValue[]
  | Map<string | number, CborValue>;

export class CborError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CborError";
  }
}

class Reader {
  #bytes: Uint8Array;
  #offset = 0;

  constructor(bytes: Uint8Array) {
    this.#bytes = bytes;
  }

  get exhausted(): boolean {
    return this.#offset === this.#bytes.length;
  }

  #take(length: number): Uint8Array {
    if (length < 0 || this.#bytes.length - this.#offset < length) {
      throw new CborError("truncated CBOR item");
    }
    const start = this.#offset;
    this.#offset += length;
    return this.#bytes.slice(start, this.#offset);
  }

  #byte(): number {
    const value = this.#bytes[this.#offset];
    if (value === undefined) throw new CborError("truncated CBOR item");
    this.#offset += 1;
    return value;
  }

  /** Reads the argument, rejecting any non-shortest encoding of it. */
  #argument(additional: number): number {
    if (additional < 24) return additional;
    if (additional === 24) {
      const value = this.#byte();
      if (value < 24) throw new CborError("non-minimal CBOR argument");
      return value;
    }
    if (additional === 25 || additional === 26 || additional === 27) {
      const width = additional === 25 ? 2 : additional === 26 ? 4 : 8;
      const bytes = this.#take(width);
      let value = 0n;
      for (const byte of bytes) value = (value << 8n) | BigInt(byte);
      const minimum = additional === 25 ? 0x100n : additional === 26 ? 0x10000n : 0x100000000n;
      if (value < minimum) throw new CborError("non-minimal CBOR argument");
      if (value > BigInt(Number.MAX_SAFE_INTEGER)) throw new CborError("CBOR argument too large");
      return Number(value);
    }
    // 28-30 are reserved; 31 is the indefinite-length marker.
    throw new CborError("unsupported CBOR argument encoding");
  }

  read(depth: number): CborValue {
    if (depth > MAX_DEPTH) throw new CborError("CBOR nesting too deep");
    const initial = this.#byte();
    const major = initial >> 5;
    const additional = initial & 0x1f;

    if (major === MAJOR_SIMPLE) {
      if (additional === 20) return false;
      if (additional === 21) return true;
      if (additional === 22) return null;
      throw new CborError("unsupported CBOR simple value");
    }

    const argument = this.#argument(additional);
    switch (major) {
      case MAJOR_UNSIGNED:
        return argument;
      case MAJOR_NEGATIVE:
        return -1 - argument;
      case MAJOR_BYTES:
        return this.#take(argument);
      case MAJOR_TEXT:
        return new TextDecoder("utf-8", { fatal: true }).decode(this.#take(argument));
      case MAJOR_ARRAY: {
        const items: CborValue[] = [];
        for (let index = 0; index < argument; index += 1) items.push(this.read(depth + 1));
        return items;
      }
      case MAJOR_MAP: {
        const entries = new Map<string | number, CborValue>();
        for (let index = 0; index < argument; index += 1) {
          const key = this.read(depth + 1);
          if (typeof key !== "string" && typeof key !== "number") {
            throw new CborError("unsupported CBOR map key");
          }
          if (entries.has(key)) throw new CborError("duplicate CBOR map key");
          entries.set(key, this.read(depth + 1));
        }
        return entries;
      }
      case MAJOR_TAG: {
        // Only the COSE_Sign1 wrapper, and only as the outermost item: NSM
        // emits no tags inside the attestation payload, so accepting one at
        // depth would widen the grammar for no reason.
        if (argument !== COSE_SIGN1_TAG || depth !== 0) {
          throw new CborError("unsupported CBOR tag");
        }
        return this.read(depth + 1);
      }
      default:
        throw new CborError("unsupported CBOR major type");
    }
  }
}

/** Decodes one deterministic CBOR item and rejects trailing bytes. */
export function decodeCbor(bytes: Uint8Array): CborValue {
  const reader = new Reader(bytes);
  const value = reader.read(0);
  if (!reader.exhausted) throw new CborError("trailing bytes after CBOR item");
  return value;
}

function encodeHead(major: number, argument: number): number[] {
  if (!Number.isSafeInteger(argument) || argument < 0) {
    throw new CborError("unencodable CBOR argument");
  }
  const prefix = major << 5;
  if (argument < 24) return [prefix | argument];
  if (argument < 0x100) return [prefix | 24, argument];
  if (argument < 0x10000) return [prefix | 25, argument >> 8, argument & 0xff];
  if (argument < 0x100000000) {
    return [prefix | 26, (argument >>> 24) & 0xff, (argument >>> 16) & 0xff, (argument >>> 8) & 0xff, argument & 0xff];
  }
  const high = Math.floor(argument / 0x100000000);
  const low = argument >>> 0;
  return [
    prefix | 27,
    (high >>> 24) & 0xff, (high >>> 16) & 0xff, (high >>> 8) & 0xff, high & 0xff,
    (low >>> 24) & 0xff, (low >>> 16) & 0xff, (low >>> 8) & 0xff, low & 0xff,
  ];
}

/**
 * Encodes the COSE `Sig_structure` that ES384 signs:
 * `["Signature1", protected, external_aad, payload]`.
 */
export function encodeCoseSigStructure(
  protectedHeaders: Uint8Array,
  externalAad: Uint8Array,
  payload: Uint8Array,
): Uint8Array {
  const context = new TextEncoder().encode("Signature1");
  const parts: number[] = [...encodeHead(MAJOR_ARRAY, 4), ...encodeHead(MAJOR_TEXT, context.length), ...context];
  for (const item of [protectedHeaders, externalAad, payload]) {
    parts.push(...encodeHead(MAJOR_BYTES, item.length), ...item);
  }
  return Uint8Array.from(parts);
}
