"use client";

import React, { createContext, useContext, useMemo } from "react";
import {
  useStableConfig,
  useTvcConnection,
  type TvcConnectionStatus,
} from "./use-tvc-connection.js";
import type { VerifiedConnection } from "../client/connection.js";
import { createTvcClient, type TvcClient, type TvcClientConfig } from "../wallet/client.js";

export type TvcWalletConnectionStatus = TvcConnectionStatus;

export type TvcWalletContextValue = {
  client: TvcClient;
  connection: VerifiedConnection | null;
  status: TvcWalletConnectionStatus;
  errorCode: string | null;
  connect(): Promise<VerifiedConnection>;
};

const Context = createContext<TvcWalletContextValue | null>(null);

export function TvcWalletProvider({
  config,
  children,
}: {
  config: TvcClientConfig;
  children: React.ReactNode;
}) {
  const stableConfig = useStableConfig(config);
  const client = useMemo(() => createTvcClient(stableConfig), [stableConfig]);
  const connection = useTvcConnection(client);
  const value = useMemo(() => ({ client, ...connection }), [client, connection]);
  return <Context.Provider value={value}>{children}</Context.Provider>;
}

export function useTvcWallet(): TvcWalletContextValue {
  const value = useContext(Context);
  if (!value) throw new Error("useTvcWallet must be used within TvcWalletProvider");
  return value;
}
