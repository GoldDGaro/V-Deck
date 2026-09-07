// @vitest-environment jsdom
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
  waitFor,
} from "@testing-library/react";
import type { ComponentProps, ReactNode } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DefinePluginFn, Plugin } from "@decky/api";
import type { ButtonItemProps, TextFieldProps } from "@decky/ui";
import type { Connection, ImportValidation, SnapshotResponse } from "./types";

const mocks = vi.hoisted(() => ({
  getSnapshot: vi.fn(),
  validateImport: vi.fn(),
  importConnection: vi.fn(),
  logImportEvent: vi.fn(),
  openFilePicker: vi.fn(),
  toast: vi.fn(),
  callable: vi.fn(),
  connect: vi.fn(),
  disconnect: vi.fn(),
  deleteConnection: vi.fn(),
  getDiagnostics: vi.fn(),
  checkExternalIp: vi.fn(),
}));

vi.mock("@decky/api", () => ({
  FileSelectionType: { FILE: 0, FOLDER: 1 },
  definePlugin: (factory: DefinePluginFn) => factory,
  openFilePicker: mocks.openFilePicker,
  toaster: { toast: mocks.toast },
  callable: (method: string) => {
    mocks.callable(method);
    const routes: Record<string, unknown> = {
      get_snapshot: mocks.getSnapshot,
      validate_import: mocks.validateImport,
      import_connection: mocks.importConnection,
      log_import_event: mocks.logImportEvent,
      connect: mocks.connect,
      disconnect: mocks.disconnect,
      delete_connection: mocks.deleteConnection,
      get_diagnostics: mocks.getDiagnostics,
      check_external_ip: mocks.checkExternalIp,
    };
    return routes[method] ?? vi.fn();
  },
}));

// Decky resolves these controls from proprietary Steam webpack modules. Use
// their public DOM/event contract; this does not simulate Steam's focus router.
vi.mock("@decky/ui", () => ({
  ButtonItem: ({ children, disabled, onClick }: ButtonItemProps) => (
    <button
      disabled={disabled}
      onClick={(event) => onClick?.(event.nativeEvent)}
    >
      {children}
    </button>
  ),
  DialogButton: (props: ComponentProps<"button">) => <button {...props} />,
  TextField: ({ label, value, onChange, bIsPassword }: TextFieldProps) => (
    <label>
      {label}
      <input
        value={value}
        onChange={onChange}
        type={bIsPassword ? "password" : "text"}
      />
    </label>
  ),
  ToggleField: ({
    label,
    checked,
    disabled,
    onChange,
  }: {
    label: ReactNode;
    checked: boolean;
    disabled?: boolean;
    onChange: (value: boolean) => void;
  }) => (
    <label>
      {label}
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(event) => onChange(event.target.checked)}
      />
    </label>
  ),
  PanelSection: ({
    title,
    children,
  }: {
    title?: string;
    children?: ReactNode;
  }) => <section aria-label={title}>{children}</section>,
  PanelSectionRow: ({ children }: { children?: ReactNode }) => (
    <div>{children}</div>
  ),
  staticClasses: {},
}));

import createPlugin from "./index";
import * as importFlow from "./import-flow";
import { getImportLog } from "./import-log";

const connection: Connection = {
  id: "imported-id",
  display_name: "AWGSD",
  protocol: "amneziawg",
  created_at: "2026-09-02T00:00:00Z",
  updated_at: "2026-09-02T00:00:00Z",
  last_used_at: null,
  last_ping_ms: null,
  source_format: ".vpn",
  requires_username_password: false,
  requires_key_passphrase: false,
  migration_source: null,
  import_error: null,
};
const emptySnapshot: SnapshotResponse = {
  success: true,
  code: "OK",
  connections: [],
  resolved_language: "en",
  backend_versions: {},
  settings: {
    desired_state: "OFF",
    active_connection_id: null,
    last_active_connection_id: null,
    auto_connect: false,
    kill_switch: false,
    kill_switch_warning_seen: false,
    language: "en",
  },
  runtime: {
    state: "DISCONNECTED",
    connection_id: null,
    interface: null,
    started_at: null,
    error_code: null,
    error_message: null,
    recovery_attempt: 0,
  },
};
const validation: ImportValidation = {
  success: true,
  code: "OK",
  path: "/home/deck/Downloads/AWGSD.vpn",
  display_name: "AWGSD",
  requires_username_password: false,
  requires_key_passphrase: false,
};

function DeckyHost({ plugin, visible }: { plugin: Plugin; visible: boolean }) {
  // Official decky-loader/frontend/src/components/PluginView.tsx visibility gate.
  return <div>{(visible || plugin.alwaysRender) && plugin.content}</div>;
}

async function selectProtocol() {
  fireEvent.click(await screen.findByRole("button", { name: "Add VPN" }));
  fireEvent.click(screen.getByRole("button", { name: "AmneziaWG" }));
}

async function clickImportAndExpectConnection() {
  const button = await screen.findByRole("button", {
    name: "Import",
  });
  expect((button as HTMLButtonElement).disabled).toBe(false);
  expect(
    (screen.getByLabelText("Connection name") as HTMLInputElement).value,
  ).toBe("AWGSD");
  const snapshotsBeforeClick = mocks.getSnapshot.mock.calls.length;
  fireEvent.click(button);
  await screen.findByText("AWGSD", { selector: "strong" });
  expect(mocks.importConnection).toHaveBeenCalledExactlyOnceWith(
    "amneziawg",
    validation.path,
    "AWGSD",
    "",
    "",
    "",
  );
  expect(mocks.getSnapshot.mock.calls.length).toBeGreaterThan(
    snapshotsBeforeClick,
  );
  expect(screen.getByRole("button", { name: "Add VPN" })).toBeTruthy();
  expect(screen.queryByRole("button", { name: "Import" })).toBeNull();
}

beforeEach(() => {
  vi.clearAllMocks();
  mocks.checkExternalIp.mockReset();
  mocks.getSnapshot.mockReset().mockResolvedValue(emptySnapshot);
  mocks.validateImport.mockReset().mockResolvedValue(validation);
  mocks.openFilePicker
    .mockReset()
    .mockResolvedValue({ path: validation.path, realpath: validation.path });
  mocks.importConnection.mockReset().mockImplementation(async () => {
    mocks.getSnapshot.mockResolvedValue({
      ...emptySnapshot,
      connections: [connection],
    });
    return { success: true, code: "OK", connection };
  });
  mocks.logImportEvent
    .mockReset()
    .mockResolvedValue({ success: true, code: "OK" });
  mocks.toast.mockReset();
  vi.spyOn(console, "info").mockImplementation(() => undefined);
  vi.spyOn(console, "error").mockImplementation(() => undefined);
  vi.spyOn(console, "warn").mockImplementation(() => undefined);
});
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

describe("rendered Decky import flow", () => {
  it("keeps the Connect error code if its following snapshot also fails", async () => {
    mocks.getSnapshot.mockResolvedValue({
      ...emptySnapshot,
      connections: [connection],
    });
    mocks.connect.mockImplementation(async () => {
      mocks.getSnapshot.mockRejectedValue(new Error("snapshot-secret"));
      return { success: false, code: "DNS_APPLY_FAILED" };
    });
    render(<DeckyHost plugin={createPlugin()} visible />);
    fireEvent.click(await screen.findByRole("checkbox"));
    expect((await screen.findByRole("alert")).textContent).toContain(
      "DNS_APPLY_FAILED",
    );
    expect(document.body.textContent).not.toContain("snapshot-secret");
    expect((screen.getByRole("checkbox") as HTMLInputElement).disabled).toBe(
      false,
    );
  });

  it("unblocks diagnostics Refresh after transport rejection without leaking exception text", async () => {
    mocks.getSnapshot.mockResolvedValue({
      ...emptySnapshot,
      connections: [connection],
    });
    mocks.getDiagnostics.mockRejectedValue(
      new Error("PrivateKey=diagnostic-secret"),
    );
    render(<DeckyHost plugin={createPlugin()} visible />);
    fireEvent.click(await screen.findByRole("button", { name: "Diagnostics" }));
    expect((await screen.findByRole("alert")).textContent).toContain(
      "DIAGNOSTICS_RPC_FAILED",
    );
    expect(document.body.textContent).not.toContain("diagnostic-secret");
    expect(
      (screen.getByRole("button", { name: "Refresh" }) as HTMLButtonElement)
        .disabled,
    ).toBe(false);
    fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
    await waitFor(() => expect(mocks.getDiagnostics).toHaveBeenCalledTimes(2));
  });

  it("allows manual OFF after recovery exhaustion while kill switch remains requested", async () => {
    mocks.getSnapshot.mockResolvedValue({
      ...emptySnapshot,
      connections: [connection],
      settings: {
        ...emptySnapshot.settings,
        desired_state: "ON",
        kill_switch: true,
      },
      runtime: {
        ...emptySnapshot.runtime,
        state: "ERROR",
        connection_id: connection.id,
        error_code: "RECOVERY_EXHAUSTED",
      },
    });
    mocks.disconnect.mockImplementation(async () => {
      mocks.getSnapshot.mockResolvedValue({
        ...emptySnapshot,
        connections: [connection],
      });
      return { success: true, code: "OK" };
    });
    render(<DeckyHost plugin={createPlugin()} visible />);
    const toggle = (await screen.findByRole("checkbox")) as HTMLInputElement;
    expect(toggle.checked).toBe(true);
    expect(toggle.disabled).toBe(false);
    fireEvent.click(toggle);
    await waitFor(() => expect(mocks.disconnect).toHaveBeenCalledTimes(1));
    await waitFor(() =>
      expect((screen.getByRole("checkbox") as HTMLInputElement).checked).toBe(
        false,
      ),
    );
    expect(mocks.connect).not.toHaveBeenCalled();
  });
  it("keeps the profile, refreshes ERROR state and displays the DNS code after failed Connect", async () => {
    mocks.getSnapshot.mockResolvedValue({
      ...emptySnapshot,
      connections: [connection],
    });
    mocks.connect.mockImplementation(async () => {
      mocks.getSnapshot.mockResolvedValue({
        ...emptySnapshot,
        connections: [connection],
        runtime: {
          ...emptySnapshot.runtime,
          state: "ERROR",
          connection_id: connection.id,
          error_code: "DNS_APPLY_FAILED",
        },
      });
      return {
        success: false,
        code: "DNS_APPLY_FAILED",
        message: "VPN DNS failed",
      };
    });
    render(<DeckyHost plugin={createPlugin()} visible />);
    fireEvent.click(await screen.findByRole("checkbox"));
    await screen.findByText(/DNS_APPLY_FAILED/);
    expect(screen.getByText("AWGSD", { selector: "strong" })).toBeTruthy();
    expect((screen.getByRole("checkbox") as HTMLInputElement).disabled).toBe(
      false,
    );
    expect(mocks.connect).toHaveBeenCalledExactlyOnceWith(connection.id);
    expect(mocks.deleteConnection).not.toHaveBeenCalled();
    expect(mocks.getSnapshot.mock.calls.length).toBeGreaterThan(1);
  });
  it("validates, renders the form, imports once and shows the fresh profile on main", async () => {
    render(<DeckyHost plugin={createPlugin()} visible />);
    await selectProtocol();
    await clickImportAndExpectConnection();
    expect(mocks.openFilePicker).toHaveBeenCalledExactlyOnceWith(
      0,
      "/home/deck/Downloads",
      true,
      true,
      undefined,
      ["conf", "vpn"],
      false,
      false,
    );
    expect(mocks.validateImport).toHaveBeenCalledExactlyOnceWith(
      "amneziawg",
      validation.path,
      validation.path,
    );
    const events = mocks.logImportEvent.mock.calls.map(([event]) => event);
    const expected = [
      "import button pressed",
      "importSelected entered",
      "RPC import_connection starting",
      "RPC import_connection returned success",
      "refresh after import started",
      "fresh snapshot",
      "import completed",
    ];
    expect(events.filter((event) => expected.includes(event))).toEqual(
      expected,
    );
    expect(mocks.logImportEvent).toHaveBeenCalledWith(
      "importSelected entered",
      expect.objectContaining({
        protocol: "amneziawg",
        filePathPresent: true,
        namePresent: true,
        busy: false,
        rpcStarted: false,
      }),
    );
  });

  it("preserves the already validated form across QAM close/reopen", async () => {
    const plugin = createPlugin();
    const host = render(<DeckyHost plugin={plugin} visible />);
    await selectProtocol();
    await screen.findByRole("button", { name: "Import" });
    host.rerender(<DeckyHost plugin={plugin} visible={false} />);
    host.rerender(<DeckyHost plugin={plugin} visible />);
    await clickImportAndExpectConnection();
  });

  it("imports WireGuard with the latest edited name and validated canonical path", async () => {
    const path = "/home/deck/Downloads/wg.conf";
    mocks.openFilePicker.mockResolvedValue({
      path,
      realpath: "/actual/wg.conf",
    });
    mocks.validateImport.mockResolvedValue({
      ...validation,
      path: "/actual/wg.conf",
      display_name: "WG",
    });
    render(<DeckyHost plugin={createPlugin()} visible />);
    fireEvent.click(await screen.findByRole("button", { name: "Add VPN" }));
    fireEvent.click(screen.getByRole("button", { name: "WireGuard" }));
    await screen.findByRole("button", { name: "Import" });
    fireEvent.change(screen.getByLabelText("Connection name"), {
      target: { value: "Edited WG" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Import" }));
    await screen.findByRole("button", { name: "Add VPN" });
    expect(mocks.validateImport).toHaveBeenCalledExactlyOnceWith(
      "wireguard",
      path,
      "/actual/wg.conf",
    );
    expect(mocks.importConnection).toHaveBeenCalledExactlyOnceWith(
      "wireguard",
      "/actual/wg.conf",
      "Edited WG",
      "",
      "",
      "",
    );
  });

  it("keeps the pending picker/form when Decky hides QAM, then imports on click", async () => {
    const plugin = createPlugin();
    const host = render(<DeckyHost plugin={plugin} visible />);
    let finishPicker!: (result: { path: string; realpath: string }) => void;
    mocks.openFilePicker.mockImplementation(
      () =>
        new Promise((resolve) => {
          finishPicker = resolve;
        }),
    );
    await selectProtocol();
    host.rerender(<DeckyHost plugin={plugin} visible={false} />);
    await act(async () => {
      finishPicker({ path: validation.path, realpath: validation.path });
    });
    await waitFor(() => expect(mocks.validateImport).toHaveBeenCalledOnce());
    host.rerender(<DeckyHost plugin={plugin} visible />);
    await clickImportAndExpectConnection();
  });

  it("disables Import for an empty or whitespace-only name", async () => {
    render(<DeckyHost plugin={createPlugin()} visible />);
    await selectProtocol();
    await screen.findByRole("button", { name: "Import" });
    for (const value of ["", "   "]) {
      fireEvent.change(screen.getByLabelText("Connection name"), {
        target: { value },
      });
      const button = screen.getByRole("button", {
        name: "Import",
      });
      expect((button as HTMLButtonElement).disabled).toBe(true);
      fireEvent.click(button);
    }
    expect(mocks.importConnection).not.toHaveBeenCalled();
  });

  it("shows an import RPC error code and keeps the form retryable", async () => {
    mocks.importConnection.mockResolvedValue({
      success: false,
      code: "CONFIG_FILE_NOT_ACCESSIBLE",
      message: "PrivateKey=secret-config-content",
    });
    render(<DeckyHost plugin={createPlugin()} visible />);
    await selectProtocol();
    fireEvent.click(await screen.findByRole("button", { name: "Import" }));
    expect(await screen.findByText(/CONFIG_FILE_NOT_ACCESSIBLE/)).toBeTruthy();
    expect(
      (
        screen.getByRole("button", {
          name: "Import",
        }) as HTMLButtonElement
      ).disabled,
    ).toBe(false);
    expect(mocks.importConnection).toHaveBeenCalledOnce();
    expect(document.body.textContent).not.toContain("secret-config-content");
  });

  it("reports pre-RPC exceptions as IMPORT_FRONTEND_FAILED with rpcStarted=false", async () => {
    vi.spyOn(importFlow, "prepareImport").mockImplementationOnce(() => {
      throw new TypeError("secret-config-content");
    });
    render(<DeckyHost plugin={createPlugin()} visible />);
    await selectProtocol();
    fireEvent.click(await screen.findByRole("button", { name: "Import" }));
    expect((await screen.findByRole("alert")).textContent).toContain(
      "IMPORT_FRONTEND_FAILED",
    );
    expect(mocks.importConnection).not.toHaveBeenCalled();
    expect(mocks.logImportEvent).toHaveBeenCalledWith(
      "import failed",
      expect.objectContaining({
        code: "IMPORT_FRONTEND_FAILED",
        stage: "preflight",
        rpcStarted: false,
        errorKind: "TypeError",
      }),
    );
    fireEvent.click(screen.getByRole("button", { name: "Import debug log" }));
    expect(
      screen.getByText(/import button pressed/, { selector: "pre" })
        .textContent,
    ).toContain("importSelected entered");
    expect(document.body.textContent).not.toContain("secret-config-content");
    expect(getImportLog().join("\n")).not.toContain("secret-config-content");
    expect(JSON.stringify(mocks.logImportEvent.mock.calls)).not.toContain(
      "secret-config-content",
    );
    await clickImportAndExpectConnection();
  });

  it("reports RPC rejection without leaking error text and clears busy", async () => {
    mocks.importConnection.mockRejectedValueOnce(
      new Error("PrivateKey=secret-config-content"),
    );
    render(<DeckyHost plugin={createPlugin()} visible />);
    await selectProtocol();
    fireEvent.click(await screen.findByRole("button", { name: "Import" }));
    expect((await screen.findByRole("alert")).textContent).toContain(
      "IMPORT_RPC_FAILED",
    );
    expect(
      (screen.getByRole("button", { name: "Import" }) as HTMLButtonElement)
        .disabled,
    ).toBe(false);
    expect(document.body.textContent).not.toContain("secret-config-content");
    expect(getImportLog().join("\n")).not.toContain("secret-config-content");
    expect(JSON.stringify(mocks.logImportEvent.mock.calls)).not.toContain(
      "secret-config-content",
    );
    expect(mocks.logImportEvent).toHaveBeenCalledWith(
      "import failed",
      expect.objectContaining({ stage: "rpc", rpcStarted: true }),
    );
  });

  it("blocks duplicate clicks until the pending RPC and refresh finish", async () => {
    let finishImport!: (value: unknown) => void;
    mocks.importConnection.mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          finishImport = resolve;
        }),
    );
    render(<DeckyHost plugin={createPlugin()} visible />);
    await selectProtocol();
    const button = await screen.findByRole("button", { name: "Import" });
    act(() => {
      fireEvent.click(button);
      fireEvent.click(button);
    });
    expect(mocks.importConnection).toHaveBeenCalledOnce();
    expect((button as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText("Import in progress…")).toBeTruthy();
    mocks.getSnapshot.mockResolvedValue({
      ...emptySnapshot,
      connections: [connection],
    });
    await act(async () => {
      finishImport({ success: true, code: "OK", connection });
    });
    await screen.findByText("AWGSD", { selector: "strong" });
    expect(mocks.importConnection).toHaveBeenCalledOnce();
  });

  it.each(["sync", "async"])(
    "imports even when the debug sink fails (%s) and the toaster throws",
    async (failure) => {
      if (failure === "sync")
        mocks.logImportEvent.mockImplementation(() => {
          throw new Error("sink failed");
        });
      else mocks.logImportEvent.mockRejectedValue(new Error("sink failed"));
      mocks.toast.mockImplementation(() => {
        throw new Error("toast failed");
      });
      render(<DeckyHost plugin={createPlugin()} visible />);
      await selectProtocol();
      await clickImportAndExpectConnection();
      expect(screen.queryByRole("alert")).toBeNull();
      expect(getImportLog().join("\n")).toContain(
        "RPC import_connection returned success",
      );
    },
  );

  it("reports a profile missing from the refreshed snapshot", async () => {
    mocks.importConnection.mockResolvedValue({
      success: true,
      code: "OK",
      connection,
    });
    render(<DeckyHost plugin={createPlugin()} visible />);
    await selectProtocol();
    fireEvent.click(await screen.findByRole("button", { name: "Import" }));
    expect((await screen.findByRole("alert")).textContent).toContain(
      "IMPORT_NOT_VISIBLE",
    );
    expect(mocks.getSnapshot).toHaveBeenCalledTimes(2);
  });

  it("reports malformed validation instead of rendering a broken form", async () => {
    mocks.validateImport.mockResolvedValue({ ...validation, path: undefined });
    render(<DeckyHost plugin={createPlugin()} visible />);
    await selectProtocol();
    expect((await screen.findByRole("alert")).textContent).toContain(
      "IMPORT_FRONTEND_FAILED",
    );
    expect(mocks.importConnection).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "Import" })).toBeNull();
  });

  it("explicitly checks device IP before and after Connect and preserves both samples", async () => {
    mocks.getSnapshot.mockResolvedValue({
      ...emptySnapshot,
      connections: [connection],
    });
    const before = {
      ip: "1.1.1.1",
      provider: "https://api.ipify.org",
      family: "IPv4",
      checked_at: "2026-09-06T10:00:00Z",
      vpn_state: "DISCONNECTED",
      connection_id: null,
      connection_name: null,
    };
    const after = {
      ...before,
      ip: "8.8.8.8",
      vpn_state: "CONNECTED",
      connection_id: connection.id,
      connection_name: connection.display_name,
    };
    const diagnostic = {
      checks: {},
      ping_ms: null,
      session_seconds: null,
      rx_bytes: 0,
      tx_bytes: 0,
    };
    mocks.getDiagnostics.mockResolvedValue({
      success: true,
      code: "OK",
      diagnostics: diagnostic,
    });
    mocks.checkExternalIp.mockResolvedValueOnce({
      success: true,
      code: "OK",
      external_ip_checks: { before, after: null },
    });
    mocks.checkExternalIp.mockResolvedValueOnce({
      success: true,
      code: "OK",
      external_ip_checks: { before, after },
    });
    render(<DeckyHost plugin={createPlugin()} visible />);
    fireEvent.click(await screen.findByRole("button", { name: "Diagnostics" }));
    await waitFor(() =>
      expect(
        (
          screen.getByRole("button", {
            name: "Check external IPv4 now",
          }) as HTMLButtonElement
        ).disabled,
      ).toBe(false),
    );
    expect(mocks.checkExternalIp).not.toHaveBeenCalled();
    fireEvent.click(
      screen.getByRole("button", { name: "Check external IPv4 now" }),
    );
    await screen.findByText("1.1.1.1");
    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    mocks.connect.mockImplementationOnce(async () => {
      mocks.getSnapshot.mockResolvedValue({
        ...emptySnapshot,
        connections: [connection],
        runtime: {
          ...emptySnapshot.runtime,
          state: "CONNECTED",
          connection_id: connection.id,
        },
      });
      return { success: true, code: "OK" };
    });
    fireEvent.click(screen.getByRole("checkbox"));
    await waitFor(() =>
      expect(mocks.connect).toHaveBeenCalledWith(connection.id),
    );
    await waitFor(() =>
      expect((screen.getByRole("checkbox") as HTMLInputElement).checked).toBe(
        true,
      ),
    );
    mocks.getDiagnostics.mockResolvedValue({
      success: true,
      code: "OK",
      diagnostics: {
        ...diagnostic,
        external_ip_checks: { before, after: null },
      },
    });
    fireEvent.click(screen.getByRole("button", { name: "Diagnostics" }));
    await waitFor(() =>
      expect(
        (
          screen.getByRole("button", {
            name: "Check external IPv4 now",
          }) as HTMLButtonElement
        ).disabled,
      ).toBe(false),
    );
    fireEvent.click(
      screen.getByRole("button", { name: "Check external IPv4 now" }),
    );
    await screen.findByText("8.8.8.8");
    expect(screen.getByText("1.1.1.1")).toBeTruthy();
    expect(
      screen.getByText("The measured IPv4 addresses differ."),
    ).toBeTruthy();
    expect(mocks.checkExternalIp).toHaveBeenCalledTimes(2);
    expect(mocks.disconnect).not.toHaveBeenCalled();
  });

  it.each(["backend", "transport"])(
    "shows a stable IP error and enables retry after %s failure",
    async (kind) => {
      mocks.getSnapshot.mockResolvedValue({
        ...emptySnapshot,
        connections: [connection],
      });
      mocks.getDiagnostics.mockResolvedValue({
        success: true,
        code: "OK",
        diagnostics: {
          checks: {},
          ping_ms: null,
          session_seconds: null,
          rx_bytes: 0,
          tx_bytes: 0,
        },
      });
      if (kind === "backend")
        mocks.checkExternalIp.mockResolvedValue({
          success: false,
          code: "EXTERNAL_IP_UNAVAILABLE",
        });
      else
        mocks.checkExternalIp.mockRejectedValue(
          new Error("PrivateKey=not-for-ui"),
        );
      render(<DeckyHost plugin={createPlugin()} visible />);
      fireEvent.click(
        await screen.findByRole("button", { name: "Diagnostics" }),
      );
      const button = screen.getByRole("button", {
        name: "Check external IPv4 now",
      }) as HTMLButtonElement;
      await waitFor(() => expect(button.disabled).toBe(false));
      fireEvent.click(button);
      expect((await screen.findByRole("alert")).textContent).toContain(
        kind === "backend"
          ? "EXTERNAL_IP_UNAVAILABLE"
          : "EXTERNAL_IP_RPC_FAILED",
      );
      expect(button.disabled).toBe(false);
      expect(document.body.textContent).not.toContain("not-for-ui");
    },
  );

  it("lays out long Russian profile actions on separate full-width rows", async () => {
    mocks.getSnapshot.mockResolvedValue({
      ...emptySnapshot,
      resolved_language: "ru",
      connections: [connection],
    });
    render(<DeckyHost plugin={createPlugin()} visible />);
    const diagnostics = await screen.findByRole("button", {
      name: "Диагностика",
    });
    for (const name of ["Диагностика", "Переименовать", "Удалить"]) {
      const button = screen.getByRole("button", { name });
      expect(button.style.width).toBe("100%");
      expect(button.style.whiteSpace).toBe("normal");
      expect(button.style.overflow).toBe("hidden");
    }
    expect(diagnostics.parentElement?.style.gridTemplateColumns).toBe(
      "minmax(0, 1fr)",
    );
  });
});
