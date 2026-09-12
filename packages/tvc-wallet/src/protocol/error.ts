export class TvcError extends Error {
  readonly code: string;

  /**
   * `code` is the stable protocol identifier callers compare against; `detail`
   * is optional human-readable context, which may include untrusted text and
   * therefore never becomes part of `code`.
   */
  constructor(code: string, detail?: string) {
    super(detail ? `${code}: ${detail}` : code);
    this.name = "TvcError";
    this.code = code;
  }
}

/** HTTP failures retain rate-limit information without returning an untrusted response body. */
export class TvcHttpError extends TvcError {
  constructor(code: string, readonly status: number, readonly retryAfter: string | null) {
    super(code, `HTTP ${status}`);
    this.name = "TvcHttpError";
  }
}
