"use client";

import { useCallback, useLayoutEffect, useMemo, useRef, useState } from "react";
import type { VerifiedConnection } from "../client/connection.js";

export type TvcConnectionStatus = "idle" | "connecting" | "verified" | "error";

type TvcConnectionState = {
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
 * A realistic config nests 6 deep, so the headroom is deliberate and pinned
 * by a test.
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
 * This means a would-be authority object holding only data would compare
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
  // Each render for a replacement client gets its own cache immediately,
  // including when a descendant connects before this hook's effects run.
  const cache = useMemo(() => ({
    client,
    connection: null as VerifiedConnection | null,
    pending: null as Promise<VerifiedConnection> | null,
  }), [client]);
  const active = useRef<typeof cache | null>(cache);
  const [state, setState] = useState({
    owner: cache,
    connection: null as VerifiedConnection | null,
    status: "idle" as TvcConnectionStatus,
    errorCode: null as string | null,
  });

  useLayoutEffect(() => {
    active.current = cache;
    return () => { active.current = null; };
  }, [cache]);

  const connect = useCallback((): Promise<VerifiedConnection> => {
    if (cache.connection) return Promise.resolve(cache.connection);
    if (cache.pending) return cache.pending;
    setState({ owner: cache, connection: null, status: "connecting", errorCode: null });
    let request: Promise<VerifiedConnection>;
    request = Promise.resolve()
      .then(() => cache.client.connectAndVerify())
      .then((verified) => {
        if (active.current !== cache) throw new Error("ConnectionSuperseded");
        cache.connection = verified;
        setState({ owner: cache, connection: verified, status: "verified", errorCode: null });
        return verified;
      })
      .catch((error: unknown) => {
        if (active.current === cache && cache.pending === request) {
          setState({
            owner: cache,
            connection: null,
            status: "error",
            errorCode: error && typeof error === "object" && "code" in error
              ? String(error.code)
              : "ConnectionFailed",
          });
        }
        throw error;
      })
      .finally(() => {
        if (cache.pending === request) cache.pending = null;
      });
    cache.pending = request;
    return request;
  }, [cache]);

  const current = state.owner === cache;
  return useMemo(
    () => ({
      connection: current ? state.connection : null,
      status: current ? state.status : "idle",
      errorCode: current ? state.errorCode : null,
      connect,
    }),
    [current, state, connect],
  );
}
