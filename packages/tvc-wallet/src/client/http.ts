import { TvcError } from "../protocol/error.js";

export function endpointUrl(endpoint: URL, path: string): URL {
  const base = new URL(endpoint);
  if (!base.pathname.endsWith("/")) base.pathname += "/";
  return new URL(path.replace(/^\/+/, ""), base);
}

export function assertExactObjectKeys(
  value: unknown,
  allowed: readonly string[],
  invalidObjectCode: string,
): void {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TvcError(invalidObjectCode);
  }
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) throw new TvcError("UnknownJsonField");
  }
}
