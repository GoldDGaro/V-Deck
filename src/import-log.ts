import { logImportEvent } from "./api";
import type { Protocol } from "./types";

export type ImportEvent =
  | "import UI mounted"
  | "import UI unmounted"
  | "protocol selected"
  | "file selected"
  | "validate_import started"
  | "validate_import succeeded"
  | "validate_import failed"
  | "file picker cancelled"
  | "import form rendered"
  | "import button pressed"
  | "importSelected entered"
  | "import blocked"
  | "RPC import_connection starting"
  | "RPC import_connection returned success"
  | "RPC import_connection returned failure"
  | "refresh after import started"
  | "fresh snapshot"
  | "import failed"
  | "import completed"
  | "toast failed";

export interface ImportLogDetails {
  protocol?: Protocol;
  filePathPresent?: boolean;
  namePresent?: boolean;
  validationPresent?: boolean;
  busy?: boolean;
  rpcStarted?: boolean;
  connections?: number;
  stage?: "validation" | "preflight" | "rpc" | "refresh" | "complete";
  code?: string;
  errorKind?: string;
}

const listeners = new Set<() => void>();
let lines: readonly string[] = [];
let sequence = 0;

export function importErrorKind(reason: unknown): string {
  // Exception messages/stacks can contain RPC arguments, paths or credentials.
  if (reason instanceof TypeError) return "TypeError";
  if (reason instanceof RangeError) return "RangeError";
  if (reason instanceof Error) return "Error";
  return typeof reason;
}

export function importErrorCode(code: unknown): string {
  return typeof code === "string" && /^[A-Z][A-Z0-9_]{0,63}$/.test(code)
    ? code
    : "RPC_FAILED";
}

export const subscribeImportLog = (listener: () => void) => {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
};
export const getImportLog = () => lines;

export function logImport(
  event: ImportEvent,
  details: ImportLogDetails = {},
): void {
  // Explicit allowlist: never spread form values or a raw RPC response/error.
  const fields: Record<string, string | number | boolean> = {
    sequence: ++sequence,
  };
  if (["amneziawg", "wireguard", "openvpn"].includes(details.protocol ?? ""))
    fields.protocol = details.protocol!;
  for (const key of [
    "filePathPresent",
    "namePresent",
    "validationPresent",
    "busy",
    "rpcStarted",
  ] as const) {
    if (typeof details[key] === "boolean") fields[key] = details[key];
  }
  if (Number.isSafeInteger(details.connections) && details.connections! >= 0)
    fields.connections = details.connections!;
  if (
    ["validation", "preflight", "rpc", "refresh", "complete"].includes(
      details.stage ?? "",
    )
  )
    fields.stage = details.stage!;
  if (details.code) fields.code = importErrorCode(details.code);
  if (
    [
      "TypeError",
      "RangeError",
      "Error",
      "string",
      "object",
      "undefined",
      "number",
      "boolean",
      "symbol",
      "function",
      "bigint",
    ].includes(details.errorKind ?? "")
  )
    fields.errorKind = details.errorKind!;
  const summary =
    event === "fresh snapshot"
      ? `fresh snapshot contains ${fields.connections ?? 0} connections`
      : event;
  lines = [
    ...lines.slice(-79),
    `${sequence}. ${summary} ${JSON.stringify(fields)}`,
  ];
  // Diagnostics must never prevent the real import, even if the sink is absent.
  try {
    console.info("[V-Deck import]", summary, fields);
  } catch {
    /* optional console */
  }
  for (const listener of listeners) {
    try {
      listener();
    } catch {
      /* diagnostics must not break import */
    }
  }
  try {
    void logImportEvent(event, fields).catch(() => undefined);
  } catch {
    /* local UI log remains available when the RPC transport is broken */
  }
}
