import { callable } from "@decky/api";
import type {
  DiagnosticsResponse,
  ImportValidation,
  Protocol,
  RpcResponse,
  SnapshotResponse,
} from "./types";

export const getSnapshot = callable<[], SnapshotResponse>("get_snapshot");
export const validateImport = callable<
  [protocol: Protocol, path: string],
  ImportValidation
>("validate_import");
export const importConnection = callable<
  [
    protocol: Protocol,
    path: string,
    name: string,
    username: string,
    password: string,
    passphrase: string,
  ],
  RpcResponse
>("import_connection");
export const connect = callable<[connectionId: string], RpcResponse>("connect");
export const disconnect = callable<[], RpcResponse>("disconnect");
export const renameConnection = callable<
  [connectionId: string, name: string],
  RpcResponse
>("rename_connection");
export const deleteConnection = callable<[connectionId: string], RpcResponse>(
  "delete_connection",
);
export const saveCredentials = callable<
  [
    connectionId: string,
    username: string,
    password: string,
    passphrase: string,
  ],
  RpcResponse
>("save_credentials");
export const updateSettings = callable<
  [
    autoConnect: boolean,
    killSwitch: boolean,
    language: string,
    warningSeen: boolean,
  ],
  RpcResponse
>("update_settings");
export const getDiagnostics = callable<
  [connectionId: string],
  DiagnosticsResponse
>("get_diagnostics");
export const exportDiagnostics = callable<
  [connectionId: string, deckyVersion: string],
  RpcResponse
>("export_diagnostics");
