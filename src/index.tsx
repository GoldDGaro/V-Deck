import {
  ButtonItem,
  DialogButton,
  PanelSection,
  PanelSectionRow,
  TextField,
  ToggleField,
  staticClasses,
} from "@decky/ui";
import {
  FileSelectionType,
  definePlugin,
  openFilePicker,
  toaster,
} from "@decky/api";
import { useCallback, useEffect, useState } from "react";
import { FaNetworkWired } from "react-icons/fa";
import {
  connect,
  deleteConnection,
  disconnect,
  exportDiagnostics,
  getDiagnostics,
  getSnapshot,
  importConnection,
  renameConnection,
  updateSettings,
  validateImport,
} from "./api";
import { rpcErrorMessage, t, type Language, type TranslationKey } from "./i18n";
import {
  connectionStatus,
  formatBytes,
  formatDuration,
  sortConnections,
  truncateName,
} from "./model";
import type {
  Connection,
  Diagnostics,
  ImportValidation,
  Protocol,
  RpcResponse,
  Snapshot,
} from "./types";

type Page =
  | "main"
  | "protocol"
  | "import"
  | "settings"
  | "diagnostics"
  | "rename"
  | "delete";

const panelStyle: React.CSSProperties = {
  maxHeight: "calc(100vh - 150px)",
  overflowY: "auto",
  overflowX: "hidden",
};
const cardStyle: React.CSSProperties = {
  width: "100%",
  boxSizing: "border-box",
  padding: "10px 12px",
  borderRadius: 8,
  background: "rgba(255,255,255,0.06)",
  overflow: "hidden",
};
const rowStyle: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: 8,
  minWidth: 0,
};
const actionStyle: React.CSSProperties = {
  minWidth: 0,
  flex: 1,
  padding: "7px 5px",
};

function protocolLabel(protocol: Protocol): string {
  return protocol === "amneziawg"
    ? "AmneziaWG"
    : protocol === "wireguard"
      ? "WireGuard"
      : "OpenVPN";
}

function statusKey(status: string): TranslationKey {
  const values: Record<string, TranslationKey> = {
    DISCONNECTED: "disconnected",
    CONNECTING: "connecting",
    CONNECTED: "connected",
    DISCONNECTING: "disconnecting",
    RECOVERING: "recovering",
    ERROR: "error",
  };
  return values[status] ?? "disconnected";
}

function ensureSuccess(response: RpcResponse, language: Language = "en"): void {
  if (!response.success) {
    throw new Error(rpcErrorMessage(language, response.code, response.message));
  }
}

function VDeckContent(): React.ReactElement {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [page, setPage] = useState<Page>("main");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState<Connection | null>(null);
  const [protocol, setProtocol] = useState<Protocol>("amneziawg");
  const [filePath, setFilePath] = useState("");
  const [validation, setValidation] = useState<ImportValidation | null>(null);
  const [name, setName] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [diagnostics, setDiagnostics] = useState<Diagnostics | null>(null);
  const language: Language = snapshot?.resolved_language ?? "en";

  const refresh = useCallback(async () => {
    const response = await getSnapshot();
    ensureSuccess(response);
    setSnapshot(response);
  }, []);

  useEffect(() => {
    void refresh().catch((reason: unknown) => setError(String(reason)));
    const timer = window.setInterval(
      () => void refresh().catch(() => undefined),
      5000,
    );
    return () => window.clearInterval(timer);
  }, [refresh]);

  const run = useCallback(
    async (operation: () => Promise<RpcResponse>, after?: () => void) => {
      setBusy(true);
      setError("");
      try {
        ensureSuccess(await operation(), language);
        await refresh();
        after?.();
      } catch (reason: unknown) {
        setError(reason instanceof Error ? reason.message : String(reason));
      } finally {
        setBusy(false);
      }
    },
    [language, refresh],
  );

  const beginImport = async (nextProtocol: Protocol) => {
    setProtocol(nextProtocol);
    setError("");
    const extensions =
      nextProtocol === "amneziawg"
        ? ["conf", "vpn"]
        : nextProtocol === "wireguard"
          ? ["conf"]
          : ["ovpn"];
    try {
      const picked = await openFilePicker(
        FileSelectionType.FILE,
        "/home/deck/Downloads",
        true,
        false,
        undefined,
        extensions,
        false,
        false,
        1,
      );
      const path = picked.realpath || picked.path;
      const checked = await validateImport(nextProtocol, path);
      ensureSuccess(checked, language);
      setFilePath(path);
      setValidation(checked);
      setName(checked.display_name);
      setPage("import");
    } catch (reason: unknown) {
      if (typeof reason === "string" && reason.toLowerCase().includes("cancel"))
        return;
      setError(reason instanceof Error ? reason.message : String(reason));
    }
  };

  const importSelected = () =>
    run(
      () =>
        importConnection(
          protocol,
          filePath,
          name,
          username,
          password,
          passphrase,
        ),
      () => {
        toaster.toast({ title: "V-Deck", body: t(language, "imported") });
        setPage("main");
        setUsername("");
        setPassword("");
        setPassphrase("");
      },
    );

  const openDiagnostics = async (connection: Connection) => {
    setSelected(connection);
    setDiagnostics(null);
    setPage("diagnostics");
    setBusy(true);
    const response = await getDiagnostics(connection.id);
    setBusy(false);
    if (response.success) setDiagnostics(response.diagnostics);
    else setError(response.message ?? response.code);
  };

  if (!snapshot) {
    return <PanelSection title={t(language, "loading")} />;
  }

  const errorView = error ? (
    <PanelSectionRow>
      <div style={{ ...cardStyle, color: "#ff9d9d", overflowWrap: "anywhere" }}>
        {error}
      </div>
    </PanelSectionRow>
  ) : null;

  if (page === "protocol") {
    return (
      <div style={panelStyle}>
        <PanelSection title={t(language, "chooseProtocol")}>
          {errorView}
          {(["amneziawg", "wireguard", "openvpn"] as Protocol[]).map((item) => (
            <PanelSectionRow key={item}>
              <ButtonItem layout="below" onClick={() => void beginImport(item)}>
                {protocolLabel(item)}
              </ButtonItem>
            </PanelSectionRow>
          ))}
          <PanelSectionRow>
            <ButtonItem layout="below" onClick={() => setPage("main")}>
              {t(language, "back")}
            </ButtonItem>
          </PanelSectionRow>
        </PanelSection>
      </div>
    );
  }

  if (page === "import") {
    return (
      <div style={panelStyle}>
        <PanelSection
          title={`${t(language, "import")} · ${protocolLabel(protocol)}`}
        >
          {errorView}
          <PanelSectionRow>
            <div style={{ ...cardStyle, overflowWrap: "anywhere" }}>
              {filePath}
            </div>
          </PanelSectionRow>
          <PanelSectionRow>
            <TextField
              label={t(language, "connectionName")}
              value={name}
              onChange={(event) => setName(event.target.value)}
            />
          </PanelSectionRow>
          {validation?.requires_username_password ? (
            <>
              <PanelSectionRow>
                <TextField
                  label={t(language, "username")}
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                />
              </PanelSectionRow>
              <PanelSectionRow>
                <TextField
                  label={t(language, "password")}
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  bIsPassword
                />
              </PanelSectionRow>
            </>
          ) : null}
          {validation?.requires_key_passphrase ? (
            <PanelSectionRow>
              <TextField
                label={t(language, "passphrase")}
                value={passphrase}
                onChange={(event) => setPassphrase(event.target.value)}
                bIsPassword
              />
            </PanelSectionRow>
          ) : null}
          <PanelSectionRow>
            <ButtonItem
              layout="below"
              disabled={busy || !name.trim()}
              onClick={importSelected}
            >
              {t(language, "import")}
            </ButtonItem>
          </PanelSectionRow>
          <PanelSectionRow>
            <ButtonItem layout="below" onClick={() => setPage("main")}>
              {t(language, "cancel")}
            </ButtonItem>
          </PanelSectionRow>
        </PanelSection>
      </div>
    );
  }

  if (page === "settings") {
    const saveSettings = (
      autoConnect: boolean,
      killSwitch: boolean,
      nextLanguage: string,
      warningSeen: boolean,
    ) =>
      run(() =>
        updateSettings(autoConnect, killSwitch, nextLanguage, warningSeen),
      );
    const requestKillSwitch = (enabled: boolean) => {
      if (enabled && !snapshot.settings.kill_switch_warning_seen) {
        return;
      }
      void saveSettings(
        snapshot.settings.auto_connect,
        enabled,
        snapshot.settings.language,
        snapshot.settings.kill_switch_warning_seen,
      );
    };
    return (
      <div style={panelStyle}>
        <PanelSection title={t(language, "settings")}>
          {errorView}
          <PanelSectionRow>
            <ToggleField
              label={t(language, "autoConnect")}
              checked={snapshot.settings.auto_connect}
              onChange={(value) =>
                void saveSettings(
                  value,
                  snapshot.settings.kill_switch,
                  snapshot.settings.language,
                  snapshot.settings.kill_switch_warning_seen,
                )
              }
            />
          </PanelSectionRow>
          <PanelSectionRow>
            <ToggleField
              label={t(language, "killSwitch")}
              checked={snapshot.settings.kill_switch}
              onChange={requestKillSwitch}
            />
          </PanelSectionRow>
          {!snapshot.settings.kill_switch_warning_seen ? (
            <PanelSectionRow>
              <div style={cardStyle}>
                <div style={{ marginBottom: 8 }}>
                  {t(language, "killWarning")}
                </div>
                <DialogButton
                  onClick={() =>
                    void saveSettings(
                      snapshot.settings.auto_connect,
                      true,
                      snapshot.settings.language,
                      true,
                    )
                  }
                >
                  {t(language, "confirm")}
                </DialogButton>
              </div>
            </PanelSectionRow>
          ) : null}
          <PanelSectionRow>
            <div style={{ ...cardStyle, fontWeight: 600 }}>
              {t(language, "language")}
            </div>
          </PanelSectionRow>
          {(["automatic", "ru", "en"] as const).map((value) => (
            <PanelSectionRow key={value}>
              <ButtonItem
                layout="below"
                onClick={() =>
                  void saveSettings(
                    snapshot.settings.auto_connect,
                    snapshot.settings.kill_switch,
                    value,
                    snapshot.settings.kill_switch_warning_seen,
                  )
                }
              >
                {value === "automatic"
                  ? t(language, "automatic")
                  : value === "ru"
                    ? t(language, "russian")
                    : t(language, "english")}
                {snapshot.settings.language === value ? " ✓" : ""}
              </ButtonItem>
            </PanelSectionRow>
          ))}
          <PanelSectionRow>
            <ButtonItem layout="below" onClick={() => setPage("main")}>
              {t(language, "back")}
            </ButtonItem>
          </PanelSectionRow>
        </PanelSection>
      </div>
    );
  }

  if (page === "diagnostics" && selected) {
    const refreshDiagnostics = () => openDiagnostics(selected);
    return (
      <div style={panelStyle}>
        <PanelSection
          title={`${t(language, "diagnostics")} · ${truncateName(selected.display_name, 28)}`}
        >
          {errorView}
          {diagnostics ? (
            <>
              {Object.entries(diagnostics.checks).map(([key, value]) => (
                <PanelSectionRow key={key}>
                  <div
                    style={{
                      ...cardStyle,
                      display: "flex",
                      justifyContent: "space-between",
                      gap: 8,
                    }}
                  >
                    <span>{t(language, key as TranslationKey)}</span>
                    <span style={{ textAlign: "right" }}>
                      {value.status === "OK"
                        ? "✓"
                        : value.status === "ERROR"
                          ? "✕"
                          : value.status === "WARNING"
                            ? "⚠"
                            : "—"}
                      {value.detail ? ` ${value.detail}` : ""}
                    </span>
                  </div>
                </PanelSectionRow>
              ))}
              <PanelSectionRow>
                <div style={cardStyle}>
                  {t(language, "external_ip")}: {diagnostics.external_ip ?? "—"}
                </div>
              </PanelSectionRow>
              <PanelSectionRow>
                <div style={cardStyle}>
                  {t(language, "ping")}:{" "}
                  {diagnostics.ping_ms === null
                    ? "—"
                    : `${diagnostics.ping_ms} ms`}
                </div>
              </PanelSectionRow>
              <PanelSectionRow>
                <div style={cardStyle}>
                  {t(language, "session")}:{" "}
                  {formatDuration(diagnostics.session_seconds)}
                </div>
              </PanelSectionRow>
              <PanelSectionRow>
                <div style={cardStyle}>
                  {t(language, "received")}: {formatBytes(diagnostics.rx_bytes)}{" "}
                  · {t(language, "sent")}: {formatBytes(diagnostics.tx_bytes)}
                </div>
              </PanelSectionRow>
            </>
          ) : (
            <PanelSectionRow>
              <div style={cardStyle}>{t(language, "loading")}</div>
            </PanelSectionRow>
          )}
          <PanelSectionRow>
            <ButtonItem
              layout="below"
              disabled={busy}
              onClick={() => void refreshDiagnostics()}
            >
              {t(language, "refresh")}
            </ButtonItem>
          </PanelSectionRow>
          <PanelSectionRow>
            <ButtonItem
              layout="below"
              onClick={() =>
                void run(
                  () => exportDiagnostics(selected.id, ""),
                  () =>
                    toaster.toast({
                      title: "V-Deck",
                      body: t(language, "reportSaved"),
                    }),
                )
              }
            >
              {t(language, "exportReport")}
            </ButtonItem>
          </PanelSectionRow>
          <PanelSectionRow>
            <ButtonItem layout="below" onClick={() => setPage("main")}>
              {t(language, "back")}
            </ButtonItem>
          </PanelSectionRow>
        </PanelSection>
      </div>
    );
  }

  if (page === "rename" && selected) {
    return (
      <div style={panelStyle}>
        <PanelSection title={t(language, "rename")}>
          {errorView}
          <PanelSectionRow>
            <TextField
              label={t(language, "connectionName")}
              value={name}
              onChange={(event) => setName(event.target.value)}
            />
          </PanelSectionRow>
          <PanelSectionRow>
            <ButtonItem
              layout="below"
              disabled={busy || !name.trim()}
              onClick={() =>
                void run(
                  () => renameConnection(selected.id, name),
                  () => setPage("main"),
                )
              }
            >
              {t(language, "save")}
            </ButtonItem>
          </PanelSectionRow>
          <PanelSectionRow>
            <ButtonItem layout="below" onClick={() => setPage("main")}>
              {t(language, "cancel")}
            </ButtonItem>
          </PanelSectionRow>
        </PanelSection>
      </div>
    );
  }

  if (page === "delete" && selected) {
    return (
      <div style={panelStyle}>
        <PanelSection title={t(language, "delete")}>
          {errorView}
          <PanelSectionRow>
            <div style={cardStyle}>
              {t(language, "deleteConfirm")}
              <br />
              {truncateName(selected.display_name)}
            </div>
          </PanelSectionRow>
          <PanelSectionRow>
            <ButtonItem
              layout="below"
              disabled={busy}
              onClick={() =>
                void run(
                  () => deleteConnection(selected.id),
                  () => setPage("main"),
                )
              }
            >
              {t(language, "confirm")}
            </ButtonItem>
          </PanelSectionRow>
          <PanelSectionRow>
            <ButtonItem layout="below" onClick={() => setPage("main")}>
              {t(language, "cancel")}
            </ButtonItem>
          </PanelSectionRow>
        </PanelSection>
      </div>
    );
  }

  const connections = sortConnections(snapshot.connections);
  return (
    <div style={panelStyle}>
      <PanelSection>
        {errorView}
        {connections.length === 0 ? (
          <PanelSectionRow>
            <div style={cardStyle}>{t(language, "noConnections")}</div>
          </PanelSectionRow>
        ) : null}
        {connections.map((connection) => {
          const status = connectionStatus(connection, snapshot.runtime);
          const active =
            snapshot.runtime.connection_id === connection.id &&
            status === "CONNECTED";
          const transitional = [
            "CONNECTING",
            "DISCONNECTING",
            "RECOVERING",
          ].includes(status);
          return (
            <PanelSectionRow key={connection.id}>
              <div style={cardStyle}>
                <div style={{ ...rowStyle, justifyContent: "space-between" }}>
                  <strong
                    style={{
                      overflow: "hidden",
                      textOverflow: "ellipsis",
                      whiteSpace: "nowrap",
                    }}
                    title={connection.display_name}
                  >
                    {truncateName(connection.display_name)}
                  </strong>
                  <span style={{ flexShrink: 0 }}>
                    {connection.last_ping_ms === null
                      ? "—"
                      : `${connection.last_ping_ms} ms`}
                  </span>
                </div>
                <div
                  style={{
                    ...rowStyle,
                    justifyContent: "space-between",
                    marginTop: 4,
                  }}
                >
                  <span>{protocolLabel(connection.protocol)}</span>
                  <span>
                    {t(
                      language,
                      statusKey(connection.import_error ? "ERROR" : status),
                    )}
                  </span>
                </div>
                {connection.import_error ? (
                  <div
                    style={{
                      marginTop: 6,
                      color: "#ff9d9d",
                      overflowWrap: "anywhere",
                    }}
                  >
                    {t(language, "migrationFailed")}: {connection.import_error}
                  </div>
                ) : null}
                <ToggleField
                  label={
                    active
                      ? t(language, "connected")
                      : t(language, statusKey(status))
                  }
                  checked={active}
                  disabled={
                    busy || transitional || Boolean(connection.import_error)
                  }
                  onChange={(value) =>
                    void run(() =>
                      value ? connect(connection.id) : disconnect(),
                    )
                  }
                />
                <div style={{ ...rowStyle, marginTop: 6 }}>
                  <DialogButton
                    style={actionStyle}
                    onClick={() => void openDiagnostics(connection)}
                  >
                    {t(language, "diagnostics")}
                  </DialogButton>
                  <DialogButton
                    style={actionStyle}
                    onClick={() => {
                      setSelected(connection);
                      setName(connection.display_name);
                      setPage("rename");
                    }}
                  >
                    {t(language, "rename")}
                  </DialogButton>
                  <DialogButton
                    style={actionStyle}
                    onClick={() => {
                      setSelected(connection);
                      setPage("delete");
                    }}
                  >
                    {t(language, "delete")}
                  </DialogButton>
                </div>
              </div>
            </PanelSectionRow>
          );
        })}
        <PanelSectionRow>
          <ButtonItem layout="below" onClick={() => setPage("protocol")}>
            {t(language, "addVpn")}
          </ButtonItem>
        </PanelSectionRow>
        <PanelSectionRow>
          <ButtonItem layout="below" onClick={() => setPage("settings")}>
            {t(language, "settings")}
          </ButtonItem>
        </PanelSectionRow>
      </PanelSection>
    </div>
  );
}

export default definePlugin(() => ({
  name: "V-Deck",
  titleView: <div className={staticClasses.Title}>V-Deck</div>,
  content: <VDeckContent />,
  icon: <FaNetworkWired />,
  onDismount() {},
}));
