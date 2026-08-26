"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { VerifiedConnection } from "../client/connection.js";

export type TvcConnectionStatus = "idle" | "connecting" | "verified" | "error";

export type TvcConnectionState = {
  connection: VerifiedConnection | null;
  status: TvcConnectionStatus;
  errorCode: string | null;
  connect(): Promise<VerifiedConnection>;
};

/**
 * Bounds the walk so a cyclic or pathological config terminates instead of
 * overflowing the stack. Crossing it is not an error, just a conservative
 * "changed" answer, so the margin over a real config matters: exceeding it
 * silently reinstates the per-render rebuild this hook exists to prevent.
 * A realistic config nests 6 deep, and `recovery_binding` carries arbitrary
 * JSON, so the headroom is deliberate and pinned by a test.
 */
const MAX_CONFIG_DEPTH = 16;

function isPlainContainer(value: object): boolean {
  const prototype = Object.getPrototypeOf(value) as object | null;
  return prototype === Object.prototype || prototype === Array.prototype || prototype === null;
}

/**
 * Structural equality for provider config.
 *
 * Plain objects and arrays are compared by value so that inline literals at any
 * depth (`operations={{ walletDescriptor, authorizer }}`) do not read as a
 * change. Class instances, typed arrays, `Map`, and the like are compared by
 * identity. Functions are too, which is what makes a rebuilt `authorizer`,
 * `transport`, or `resolveBootProof` read as a different client: those are
 * plain objects, so they compare structurally, but the closures they carry
 * never match across instances. `URL` is special-cased because an endpoint is
 * naturally rebuilt from a string.
 *
 * Note this means a would-be authority object holding only data would compare
 * equal across instances; every such object in the config carries a function.
 */
export function configsEqual(left: unknown, right: unknown, depth = 0): boolean {
  if (Object.is(left, right)) return true;
  if (depth > MAX_CONFIG_DEPTH) return false;
  if (left instanceof URL && right instanceof URL) return left.href === right.href;
  if (
    typeof left !== "object" ||
    typeof right !== "object" ||
    left === null ||
    right === null ||
    Array.isArray(left) !== Array.isArray(right) ||
    !isPlainContainer(left) ||
    !isPlainContainer(right)
  ) {
    return false;
  }
  const keys = Object.keys(left);
  if (keys.length !== Object.keys(right).length) return false;
  return keys.every(
    (key) =>
      Object.hasOwn(right, key) &&
      configsEqual(
        (left as Record<string, unknown>)[key],
        (right as Record<string, unknown>)[key],
        depth + 1,
      ),
  );
}

/**
 * Holds a config object's identity stable while its contents are unchanged.
 *
 * Callers naturally write `<TvcWalletProvider config={{ endpoint, ... }}>`,
 * which allocates a new object every render. Without this the client would be
 * rebuilt and the verified connection discarded on every parent re-render.
 */
export function useStableConfig<T extends object>(config: T): T {
  // Reading and writing a ref during render deviates from React's purity rule.
  // It is bounded here: the write is idempotent for a given prop identity, and
  // the worst outcome under a discarded concurrent render is returning a
  // structurally equal config from that render. The alternatives either add a
  // render pass or lose stabilization across un-flushed effects.
  const previous = useRef(config);
  if (previous.current !== config && !configsEqual(previous.current, config)) {
    previous.current = config;
  }
  return previous.current;
}

/** Single-flight `connectAndVerify` with status, shared by both profiles. */
export function useTvcConnection(client: {
  connectAndVerify(): Promise<VerifiedConnection>;
}): TvcConnectionState {
  const activeClient = useRef(client);
  const pending = useRef<Promise<VerifiedConnection> | null>(null);
  const [connection, setConnection] = useState<VerifiedConnection | null>(null);
  const [status, setStatus] = useState<TvcConnectionStatus>("idle");
  const [errorCode, setErrorCode] = useState<string | null>(null);

  useEffect(() => {
    activeClient.current = client;
    pending.current = null;
    setConnection(null);
    setStatus("idle");
    setErrorCode(null);
  }, [client]);

  const connect = useCallback((): Promise<VerifiedConnection> => {
    if (connection) return Promise.resolve(connection);
    if (pending.current) return pending.current;
    setStatus("connecting");
    setErrorCode(null);
    const request = client
      .connectAndVerify()
      .then((verified) => {
        if (activeClient.current !== client) throw new Error("ConnectionSuperseded");
        setConnection(verified);
        setStatus("verified");
        return verified;
      })
      .catch((error: unknown) => {
        setErrorCode(
          error && typeof error === "object" && "code" in error
            ? String(error.code)
            : "ConnectionFailed",
        );
        setStatus("error");
        throw error;
      })
      .finally(() => {
        pending.current = null;
      });
    pending.current = request;
    return request;
  }, [client, connection]);

  return useMemo(
    () => ({ connection, status, errorCode, connect }),
    [connection, status, errorCode, connect],
  );
}
