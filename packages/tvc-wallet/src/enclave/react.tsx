"use client";

import React, { createContext, useContext, useMemo } from "react";
import {
  useStableConfig,
  useTvcConnection,
  type TvcConnectionStatus,
} from "../react/use-tvc-connection.js";
import type { VerifiedConnection } from "../client/connection.js";
import {
  createTvcEnclaveWalletClient,
  type TvcEnclaveWalletClient,
  type TvcEnclaveWalletClientConfig,
} from "./index.js";

export type TvcEnclaveConnectionStatus = TvcConnectionStatus;

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
  const stableConfig = useStableConfig(config);
  const client = useMemo(() => createTvcEnclaveWalletClient(stableConfig), [stableConfig]);
  const connection = useTvcConnection(client);
  const value = useMemo(() => ({ client, ...connection }), [client, connection]);
  return <Context.Provider value={value}>{children}</Context.Provider>;
}

export function useTvcEnclaveWallet(): TvcEnclaveWalletContextValue {
  const value = useContext(Context);
  if (!value) throw new Error("useTvcEnclaveWallet must be used within TvcEnclaveWalletProvider");
  return value;
}
