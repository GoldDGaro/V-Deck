export type Protocol = "amneziawg" | "wireguard" | "openvpn";
export type RuntimeStatus =
  | "DISCONNECTED"
  | "CONNECTING"
  | "CONNECTED"
  | "DISCONNECTING"
  | "RECOVERING"
  | "ERROR";

export interface Connection {
  id: string;
  display_name: string;
  protocol: Protocol;
  created_at: string;
  updated_at: string;
  last_used_at: string | null;
  last_ping_ms: number | null;
  source_format: string;
  requires_username_password: boolean;
  requires_key_passphrase: boolean;
  migration_source: string | null;
  import_error: string | null;
}

export interface Settings {
  desired_state: "ON" | "OFF";
  active_connection_id: string | null;
  last_active_connection_id: string | null;
  auto_connect: boolean;
  kill_switch: boolean;
  kill_switch_warning_seen: boolean;
  language: "automatic" | "ru" | "en";
}

export interface Runtime {
  state: RuntimeStatus;
  connection_id: string | null;
  interface: string | null;
  started_at: string | null;
  error_code: string | null;
  error_message: string | null;
  recovery_attempt: number;
}

export interface Snapshot {
  settings: Settings;
  runtime: Runtime;
  connections: Connection[];
  resolved_language: "ru" | "en";
  backend_versions: Record<string, string>;
}

export interface RpcResponse {
  success: boolean;
  code: string;
  message?: string;
  connection?: Connection;
  connections_count?: number;
  path?: string;
}

export type SnapshotResponse = RpcResponse & Snapshot;

export interface ImportValidation extends RpcResponse {
  path: string;
  display_name: string;
  requires_username_password: boolean;
  requires_key_passphrase: boolean;
}

export interface DiagnosticCheck {
  status: "OK" | "WARNING" | "ERROR" | "NOT_APPLICABLE" | "UNKNOWN";
  detail: string;
}

export interface Diagnostics {
  external_ip_checks?: ExternalIpChecks;
  overall: "OK" | "WARNING" | "ERROR";
  protocol: Protocol;
  checks: Record<string, DiagnosticCheck>;
  external_ip: string | null;
  ping_ms: number | null;
  session_seconds: number | null;
  rx_bytes: number;
  tx_bytes: number;
  interface: string | null;
  state: RuntimeStatus;
}

export interface DiagnosticsResponse extends RpcResponse {
  diagnostics: Diagnostics;
}

export interface ExternalIpSample {
  ip: string;
  family: "IPv4";
  provider: string;
  checked_at: string;
  vpn_state: RuntimeStatus;
  connection_id: string | null;
  connection_name: string | null;
}

export interface ExternalIpChecks {
  before: ExternalIpSample | null;
  after: ExternalIpSample | null;
}

export interface ExternalIpResponse extends RpcResponse {
  external_ip_checks: ExternalIpChecks;
}
