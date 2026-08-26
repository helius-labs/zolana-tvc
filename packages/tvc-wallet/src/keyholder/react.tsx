"use client";

import React, { createContext, useContext, useMemo } from "react";
import {
  useStableConfig,
  useTvcConnection,
  type TvcConnectionStatus,
} from "../react/use-tvc-connection.js";
import type { VerifiedConnection } from "../client/connection.js";
import {
  createTvcKeyholderClient,
  type TvcKeyholderClient,
  type TvcKeyholderClientConfig,
} from "./index.js";

export type TvcKeyholderConnectionStatus = TvcConnectionStatus;

export type TvcKeyholderContextValue = {
  client: TvcKeyholderClient;
  connection: VerifiedConnection | null;
  status: TvcKeyholderConnectionStatus;
  errorCode: string | null;
  connect(): Promise<VerifiedConnection>;
};

const Context = createContext<TvcKeyholderContextValue | null>(null);

export function TvcKeyholderProvider({
  config,
  children,
}: {
  config: TvcKeyholderClientConfig;
  children: React.ReactNode;
}) {
  const stableConfig = useStableConfig(config);
  const client = useMemo(() => createTvcKeyholderClient(stableConfig), [stableConfig]);
  const connection = useTvcConnection(client);
  const value = useMemo(() => ({ client, ...connection }), [client, connection]);
  return <Context.Provider value={value}>{children}</Context.Provider>;
}

export function useTvcKeyholder(): TvcKeyholderContextValue {
  const value = useContext(Context);
  if (!value) throw new Error("useTvcKeyholder must be used within TvcKeyholderProvider");
  return value;
}
