"use client";

import React, { createContext, useContext, useMemo } from "react";
import {
  createTvcWalletClient,
  type TvcWalletClient,
  type TvcWalletClientConfig,
  type VerifiedConnection,
} from "../client/index.js";
import {
  useStableConfig,
  useTvcConnection,
  type TvcConnectionStatus,
} from "./use-tvc-connection.js";

export type { TvcConnectionStatus };

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
  const stableConfig = useStableConfig(config);
  const client = useMemo(() => createTvcWalletClient(stableConfig), [stableConfig]);
  const connection = useTvcConnection(client);
  const value = useMemo(() => ({ client, ...connection }), [client, connection]);
  return <TvcWalletContext.Provider value={value}>{children}</TvcWalletContext.Provider>;
}

export function useTvcWallet(): TvcWalletContextValue {
  const value = useContext(TvcWalletContext);
  if (!value) {
    throw new Error("useTvcWallet must be used within TvcWalletProvider");
  }
  return value;
}
