import type { FilePickerRes } from "@decky/api";
import type { Snapshot } from "./types";

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
