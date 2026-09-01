import { describe, expect, it } from "vitest";
import {
  connectionStatus,
  formatBytes,
  formatDuration,
  sortConnections,
  truncateName,
} from "./model";
import type { Connection, Runtime } from "./types";

const connection = (
  id: string,
  created: string,
  last: string | null,
): Connection => ({
  id,
  display_name: id,
  protocol: "wireguard",
  created_at: created,
  updated_at: created,
  last_used_at: last,
  last_ping_ms: null,
  source_format: ".conf",
  requires_username_password: false,
  requires_key_passphrase: false,
  migration_source: null,
  import_error: null,
});

describe("frontend model", () => {
  it("sorts last-used connections first", () => {
    const values = [
      connection("old", "2020", null),
      connection("new", "2021", "2099"),
    ];
    expect(sortConnections(values).map((item) => item.id)).toEqual([
      "new",
      "old",
    ]);
  });

  it("maps runtime only to the active card", () => {
    const runtime = { connection_id: "a", state: "CONNECTING" } as Runtime;
    expect(connectionStatus(connection("a", "2020", null), runtime)).toBe(
      "CONNECTING",
    );
    expect(connectionStatus(connection("b", "2020", null), runtime)).toBe(
      "DISCONNECTED",
    );
  });

  it("formats compact diagnostics values", () => {
    expect(formatBytes(1536)).toBe("1.5 KB");
    expect(formatDuration(3720)).toBe("1 h 2 min");
    expect(truncateName("x".repeat(70))).toHaveLength(54);
  });
});
