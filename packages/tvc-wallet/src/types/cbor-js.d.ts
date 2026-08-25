declare module "cbor-js" {
  const cbor: {
    decode(data: ArrayBuffer): unknown;
    encode(value: unknown): ArrayBuffer;
  };
  export default cbor;
}
