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
  createTvcWalletClient,
  type TvcWalletClient,
  type TvcWalletClientConfig,
  type VerifiedConnection,
} from "../client/index.js";

export type TvcConnectionStatus =
  | "idle"
  | "connecting"
  | "verified"
  | "error";

export type TvcWalletContextValue = {
  client: TvcWalletClient;
  connection: VerifiedConnection | null;
  status: TvcConnectionStatus;
  errorCode: string | null;
  connect(): Promise<VerifiedConnection>;
};

const TvcWalletContext = createContext<TvcWalletContextValue | null>(null);

export function TvcWalletProvider({
  config,
  children,
}: {
  config: TvcWalletClientConfig;
  children: React.ReactNode;
}) {
  const client = useMemo(() => createTvcWalletClient(config), [config]);
  const activeClient = useRef(client);
  const [connection, setConnection] = useState<VerifiedConnection | null>(null);
  const [status, setStatus] = useState<TvcConnectionStatus>("idle");
  const [errorCode, setErrorCode] = useState<string | null>(null);
  const pending = useRef<Promise<VerifiedConnection> | null>(null);

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
        if (activeClient.current !== client) {
          throw new Error("ConnectionSuperseded");
        }
        setConnection(verified);
        setStatus("verified");
        return verified;
      })
      .catch((error: unknown) => {
        const code =
          error && typeof error === "object" && "code" in error
            ? String(error.code)
            : "ConnectionFailed";
        setErrorCode(code);
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
  return <TvcWalletContext.Provider value={value}>{children}</TvcWalletContext.Provider>;
}

export function useTvcWallet(): TvcWalletContextValue {
  const value = useContext(TvcWalletContext);
  if (!value) {
    throw new Error("useTvcWallet must be used within TvcWalletProvider");
  }
  return value;
}
