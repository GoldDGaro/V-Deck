import type { FilePickerRes } from "@decky/api";
import type { ImportValidation, Protocol, Snapshot } from "./types";

export function validateImportResponse(checked: ImportValidation): void {
  if (
    typeof checked.path !== "string" ||
    !checked.path.trim() ||
    typeof checked.display_name !== "string" ||
    typeof checked.requires_username_password !== "boolean" ||
    typeof checked.requires_key_passphrase !== "boolean"
  ) {
    throw new TypeError("INVALID_IMPORT_VALIDATION_RESPONSE");
  }
}

export function prepareImport(
  protocol: Protocol,
  path: string,
  name: string,
  validation: ImportValidation | null,
): string {
  if (
    !validation ||
    !validation.success ||
    !["wireguard", "amneziawg", "openvpn"].includes(protocol) ||
    typeof path !== "string" ||
    !path.trim() ||
    path !== validation.path ||
    typeof name !== "string" ||
    !name.trim()
  ) {
    throw new TypeError("INVALID_IMPORT_FORM_STATE");
  }
  return name.trim();
}

export function pickerRpcPaths(
  picked: FilePickerRes,
): [path: string, realpath: string] {
  const path = typeof picked?.path === "string" ? picked.path.trim() : "";
  const realpath =
    typeof picked?.realpath === "string" ? picked.realpath.trim() : "";
  if (!path && !realpath) throw new Error("FILE_PICKER_EMPTY_RESULT");
  return [path, realpath];
}

export function snapshotContainsConnection(
  snapshot: Pick<Snapshot, "connections">,
  connectionId: string,
): boolean {
  return snapshot.connections.some(
    (connection) => connection.id === connectionId,
  );
}
