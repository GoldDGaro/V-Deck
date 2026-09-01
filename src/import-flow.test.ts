import { describe, expect, it } from "vitest";
import { pickerRpcPaths, snapshotContainsConnection } from "./import-flow";
import type { Connection } from "./types";

const connection: Connection = {
  id: "connection-id",
  display_name: "Deck VPN",
  protocol: "wireguard",
  created_at: "2026-09-01T00:00:00Z",
  updated_at: "2026-09-01T00:00:00Z",
  last_used_at: null,
  last_ping_ms: null,
  source_format: ".conf",
  requires_username_password: false,
  requires_key_passphrase: false,
  migration_source: null,
  import_error: null,
};

describe("Decky import boundary", () => {
  it("preserves both picker paths for backend accessibility checks", () => {
    expect(
      pickerRpcPaths({
        path: "/home/deck/Downloads/vpn.conf",
        realpath: "/run/user/1000/doc/vpn.conf",
      }),
    ).toEqual(["/home/deck/Downloads/vpn.conf", "/run/user/1000/doc/vpn.conf"]);
  });

  it("rejects an empty picker response", () => {
    expect(() => pickerRpcPaths({ path: "", realpath: "" })).toThrow(
      "FILE_PICKER_EMPTY_RESULT",
    );
  });

  it("confirms that the imported id is visible in the refreshed snapshot", () => {
    expect(
      snapshotContainsConnection({ connections: [connection] }, connection.id),
    ).toBe(true);
    expect(snapshotContainsConnection({ connections: [] }, connection.id)).toBe(
      false,
    );
  });
});
