"use client";

import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import {
  createTvcEnclaveWalletClient,
  type TvcEnclaveWalletClient,
  type TvcEnclaveWalletClientConfig,
  type VerifiedConnection,
} from "./index.js";

export type TvcEnclaveConnectionStatus = "idle" | "connecting" | "verified" | "error";

export type TvcEnclaveWalletContextValue = {
  client: TvcEnclaveWalletClient;
  connection: VerifiedConnection | null;
  status: TvcEnclaveConnectionStatus;
  errorCode: string | null;
  connect(): Promise<VerifiedConnection>;
};

const Context = createContext<TvcEnclaveWalletContextValue | null>(null);

export function TvcEnclaveWalletProvider({
  config,
  children,
}: {
  config: TvcEnclaveWalletClientConfig;
  children: React.ReactNode;
}) {
  const client = useMemo(() => createTvcEnclaveWalletClient(config), [config]);
  const activeClient = useRef(client);
  const [connection, setConnection] = useState<VerifiedConnection | null>(null);
  const [status, setStatus] = useState<TvcEnclaveConnectionStatus>("idle");
  const [errorCode, setErrorCode] = useState<string | null>(null);
  const pending = useRef<Promise<VerifiedConnection> | null>(null);

  useEffect(() => {
    activeClient.current = client;
    pending.current = null;
    setConnection(null);
    setStatus("idle");
    setErrorCode(null);
  }, [client]);

  const connect = useCallback(() => {
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

  const value = useMemo(
    () => ({ client, connection, status, errorCode, connect }),
    [client, connection, status, errorCode, connect],
  );
  return <Context.Provider value={value}>{children}</Context.Provider>;
}

export function useTvcEnclaveWallet(): TvcEnclaveWalletContextValue {
  const value = useContext(Context);
  if (!value) throw new Error("useTvcEnclaveWallet must be used within TvcEnclaveWalletProvider");
  return value;
}
