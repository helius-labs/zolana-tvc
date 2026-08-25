import { gcm } from "@noble/ciphers/aes";
import { p256 } from "@noble/curves/p256";
import { hmac } from "@noble/hashes/hmac";
import { sha512 } from "@noble/hashes/sha512";
import {
  QOS_ENCRYPTION_HMAC_MESSAGE,
  QOS_P256_PUBLIC_LEN,
  SEC1_UNCOMPRESSED_LEN,
} from "../protocol/constants.js";
import { TvcError } from "../protocol/error.js";
import { parseUncompressedSec1 } from "./p256.js";

const te = new TextEncoder();
const AES_GCM_TAG_LEN = 16;

export type QosP256Public = {
  encryption: Uint8Array;
  signing: Uint8Array;
};

export function parseQosP256Public(bytes: Uint8Array): QosP256Public {
  if (bytes.length !== QOS_P256_PUBLIC_LEN) {
    throw new TvcError("InvalidPublicKey");
  }
  const encryption = parseUncompressedSec1(
    bytes.slice(0, SEC1_UNCOMPRESSED_LEN)
  );
  const signing = parseUncompressedSec1(bytes.slice(SEC1_UNCOMPRESSED_LEN));
  return { encryption, signing };
}

function sharedX(secret: Uint8Array, publicSec1: Uint8Array): Uint8Array {
  const shared = p256.getSharedSecret(secret, publicSec1, false);
  return shared.slice(1, 33);
}

function cipherKey(
  ephemeralPublic: Uint8Array,
  receiverPublic: Uint8Array,
  sharedSecret: Uint8Array
): Uint8Array {
  const preImage = new Uint8Array(
    ephemeralPublic.length + receiverPublic.length + sharedSecret.length
  );
  preImage.set(ephemeralPublic, 0);
  preImage.set(receiverPublic, ephemeralPublic.length);
  preImage.set(sharedSecret, ephemeralPublic.length + receiverPublic.length);
  return hmac(sha512, preImage, te.encode(QOS_ENCRYPTION_HMAC_MESSAGE)).slice(
    0,
    32
  );
}

function aad(
  ephemeralPublic: Uint8Array,
  receiverPublic: Uint8Array
): Uint8Array {
  const out = new Uint8Array(
    ephemeralPublic.length + receiverPublic.length + 2
  );
  out.set(ephemeralPublic, 0);
  out[ephemeralPublic.length] = ephemeralPublic.length;
  out.set(receiverPublic, ephemeralPublic.length + 1);
  out[out.length - 1] = receiverPublic.length;
  return out;
}

function encodeU32Le(value: number): Uint8Array {
  const out = new Uint8Array(4);
  const view = new DataView(out.buffer);
  view.setUint32(0, value, true);
  return out;
}

function decodeU32Le(bytes: Uint8Array, offset: number): number {
  return new DataView(bytes.buffer, bytes.byteOffset + offset, 4).getUint32(
    0,
    true
  );
}

export function encodeQosEnvelope(
  nonce: Uint8Array,
  ephemeralPublic: Uint8Array,
  encryptedMessage: Uint8Array
): Uint8Array {
  const out = new Uint8Array(12 + 65 + 4 + encryptedMessage.length);
  out.set(nonce, 0);
  out.set(ephemeralPublic, 12);
  out.set(encodeU32Le(encryptedMessage.length), 77);
  out.set(encryptedMessage, 81);
  return out;
}

export function decodeQosEnvelope(bytes: Uint8Array): {
  nonce: Uint8Array;
  ephemeralSenderPublic: Uint8Array;
  encryptedMessage: Uint8Array;
} {
  if (bytes.length < 81) throw new TvcError("InvalidEncryptedEnvelope");
  const nonce = bytes.slice(0, 12);
  const ephemeralSenderPublic = bytes.slice(12, 77);
  const messageLen = decodeU32Le(bytes, 77);
  if (bytes.length !== 81 + messageLen)
    throw new TvcError("InvalidEncryptedEnvelope");
  const encryptedMessage = bytes.slice(81);
  if (encryptedMessage.length < AES_GCM_TAG_LEN) {
    throw new TvcError("InvalidEncryptedEnvelope");
  }
  return { nonce, ephemeralSenderPublic, encryptedMessage };
}

export function qosEncryptWith(
  receiverEncryptionSec1: Uint8Array,
  plaintext: Uint8Array,
  ephemeralSecret: Uint8Array,
  nonce: Uint8Array
): Uint8Array {
  const receiver = parseUncompressedSec1(receiverEncryptionSec1);
  const ephemeralPublic = p256.getPublicKey(ephemeralSecret, false);
  const shared = sharedX(ephemeralSecret, receiver);
  const key = cipherKey(ephemeralPublic, receiver, shared);
  const associated = aad(ephemeralPublic, receiver);
  const encryptedMessage = gcm(key, nonce, associated).encrypt(plaintext);
  return encodeQosEnvelope(nonce, ephemeralPublic, encryptedMessage);
}

export function qosEncrypt(
  receiverEncryptionSec1: Uint8Array,
  plaintext: Uint8Array
): Uint8Array {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  return qosEncryptWith(
    receiverEncryptionSec1,
    plaintext,
    p256.utils.randomPrivateKey(),
    nonce
  );
}

export function qosDecrypt(
  receiverSecret: Uint8Array,
  envelopeBytes: Uint8Array
): Uint8Array {
  const envelope = decodeQosEnvelope(envelopeBytes);
  parseUncompressedSec1(envelope.ephemeralSenderPublic);
  const receiverPublic = p256.getPublicKey(receiverSecret, false);
  const shared = sharedX(receiverSecret, envelope.ephemeralSenderPublic);
  const key = cipherKey(envelope.ephemeralSenderPublic, receiverPublic, shared);
  const associated = aad(envelope.ephemeralSenderPublic, receiverPublic);
  try {
    return gcm(key, envelope.nonce, associated).decrypt(
      envelope.encryptedMessage
    );
  } catch {
    throw new TvcError("InvalidEncryptedEnvelope");
  }
}
