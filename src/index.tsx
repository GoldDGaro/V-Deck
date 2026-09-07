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
import { useCallback, useEffect, useRef, useState } from "react";
import { FaNetworkWired } from "react-icons/fa";
import {
  checkExternalIp,
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
import { displayRpcError, t, type Language, type TranslationKey } from "./i18n";
import {
  pickerRpcPaths,
  prepareImport,
  snapshotContainsConnection,
  validateImportResponse,
} from "./import-flow";
import {
  getImportLog,
  importErrorCode,
  importErrorKind,
  logImport,
  subscribeImportLog,
} from "./import-log";
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
  ExternalIpChecks,
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
  width: "100%",
  boxSizing: "border-box",
  padding: "8px 10px",
  height: "auto",
  minHeight: 38,
  fontSize: 14,
  lineHeight: "20px",
  whiteSpace: "normal",
  overflowWrap: "anywhere",
  overflow: "hidden",
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

class DisplayedRpcError extends Error {}

function ensureSuccess(
  response: RpcResponse,
  language: Language = "en",
  heading: TranslationKey = "genericError",
): void {
  if (!response.success) {
    throw new DisplayedRpcError(displayRpcError(language, response, heading));
  }
}

function unexpectedImportError(
  language: Language,
  code:
    | "VALIDATE_IMPORT_RPC_FAILED"
    | "IMPORT_RPC_FAILED"
    | "IMPORT_NOT_VISIBLE"
    | "IMPORT_FRONTEND_FAILED"
    | "IMPORT_REFRESH_FAILED",
): string {
  return `${t(language, "importFailed")}\n${code}`;
}

function ImportDebugLog({
  language,
}: {
  language: Language;
}): React.ReactElement | null {
  const [lines, setLines] = useState(getImportLog);
  useEffect(() => {
    setLines(getImportLog());
    return subscribeImportLog(() => setLines(getImportLog()));
  }, []);
  const [expanded, setExpanded] = useState(false);
  if (!lines.length) return null;
  return (
    <PanelSectionRow>
      <ButtonItem layout="below" onClick={() => setExpanded(!expanded)}>
        {t(language, "importDebugLog")}
      </ButtonItem>
      {expanded ? (
        <pre
          style={{
            ...cardStyle,
            whiteSpace: "pre-wrap",
            overflowWrap: "anywhere",
            fontSize: 11,
          }}
        >
          {lines.join("\n")}
        </pre>
      ) : null}
    </PanelSectionRow>
  );
}

function VDeckContent(): React.ReactElement {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [page, setPage] = useState<Page>("main");
  const [busy, setBusy] = useState(false);
  const operationInFlight = useRef(false);
  const importInFlight = useRef(false);
  const pickerInFlight = useRef(false);
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
  const [ipChecks, setIpChecks] = useState<ExternalIpChecks>({
    before: null,
    after: null,
  });
  const language: Language = snapshot?.resolved_language ?? "en";

  const refresh = useCallback(async () => {
    const response = await getSnapshot();
    ensureSuccess(response);
    setSnapshot(response);
  }, []);

  useEffect(() => {
    logImport("import UI mounted");
    void refresh().catch((reason: unknown) => setError(String(reason)));
    const timer = window.setInterval(
      () =>
        void refresh().catch((reason: unknown) =>
          setError(
            reason instanceof Error ? reason.message : "SNAPSHOT_FAILED",
          ),
        ),
      5000,
    );
    return () => {
      window.clearInterval(timer);
      logImport("import UI unmounted");
    };
  }, [refresh]);

  useEffect(() => {
    if (page === "import")
      logImport("import form rendered", {
        protocol,
        filePathPresent: Boolean(filePath),
        namePresent: Boolean(name.trim()),
        validationPresent: Boolean(validation),
        busy,
      });
  }, [page, protocol, filePath, name, validation, busy]);

  const importToast = (message: string, critical = false) => {
    try {
      toaster.toast({
        title: critical ? t(language, "importFailed") : "V-Deck",
        body: message,
        critical,
      });
    } catch (reason: unknown) {
      logImport("toast failed", { errorKind: importErrorKind(reason) });
    }
  };

  const checkImportResponse = (
    response: RpcResponse,
    heading: TranslationKey = "importFailed",
  ) => {
    if (!response.success)
      throw new DisplayedRpcError(
        displayRpcError(
          language,
          { code: importErrorCode(response.code) },
          heading,
        ),
      );
  };

  const run = useCallback(
    async (operation: () => Promise<RpcResponse>, after?: () => void) => {
      if (operationInFlight.current) return;
      operationInFlight.current = true;
      setBusy(true);
      setError("");
      try {
        const response = await operation();
        if (!response.success) {
          // A snapshot outage must not replace the actual Connect/cleanup error.
          await refresh().catch(() => undefined);
          ensureSuccess(response, language);
        }
        await refresh();
        ensureSuccess(response, language);
        after?.();
      } catch (reason: unknown) {
        setError(
          reason instanceof DisplayedRpcError
            ? reason.message
            : "OPERATION_RPC_FAILED",
        );
      } finally {
        operationInFlight.current = false;
        setBusy(false);
      }
    },
    [language, refresh],
  );

  const beginImport = async (nextProtocol: Protocol) => {
    if (pickerInFlight.current || importInFlight.current) return;
    pickerInFlight.current = true;
    setBusy(true);
    setProtocol(nextProtocol);
    setError("");
    logImport("protocol selected", { protocol: nextProtocol });
    const extensions =
      nextProtocol === "amneziawg"
        ? ["conf", "vpn"]
        : nextProtocol === "wireguard"
          ? ["conf"]
          : ["ovpn"];
    let validationReturned = false;
    try {
      const picked = await openFilePicker(
        FileSelectionType.FILE,
        "/home/deck/Downloads",
        true,
        true,
        undefined,
        extensions,
        false,
        false,
      );
      const [pickedPath, pickedRealpath] = pickerRpcPaths(picked);
      logImport("file selected", {
        protocol: nextProtocol,
        filePathPresent: Boolean(pickedPath || pickedRealpath),
      });
      logImport("validate_import started", { protocol: nextProtocol });
      const checked = await validateImport(
        nextProtocol,
        pickedPath,
        pickedRealpath,
      );
      validationReturned = true;
      checkImportResponse(checked, "validationFailed");
      validateImportResponse(checked);
      logImport("validate_import succeeded", { protocol: nextProtocol });
      setFilePath(checked.path);
      setValidation(checked);
      setName(checked.display_name);
      setUsername("");
      setPassword("");
      setPassphrase("");
      setPage("import");
    } catch (reason: unknown) {
      if (reason === "User canceled") {
        logImport("file picker cancelled");
        return;
      }
      const code = validationReturned
        ? "IMPORT_FRONTEND_FAILED"
        : "VALIDATE_IMPORT_RPC_FAILED";
      logImport("validate_import failed", {
        protocol: nextProtocol,
        stage: "validation",
        code,
        errorKind: importErrorKind(reason),
      });
      const message =
        reason instanceof DisplayedRpcError
          ? reason.message
          : unexpectedImportError(language, code);
      setError(message);
      importToast(message, true);
    } finally {
      pickerInFlight.current = false;
      setBusy(false);
    }
  };

  const importSelected = async () => {
    if (importInFlight.current) {
      logImport("import blocked", { busy: true, rpcStarted: true });
      return;
    }
    let stage: "preflight" | "rpc" | "refresh" | "complete" = "preflight";
    let rpcReturned = false;
    try {
      logImport("importSelected entered", {
        protocol,
        filePathPresent: Boolean(filePath),
        namePresent: Boolean(name?.trim()),
        validationPresent: Boolean(validation),
        busy,
        rpcStarted: false,
      });
      importInFlight.current = true;
      setBusy(true);
      setError("");
      const importName = prepareImport(protocol, filePath, name, validation);
      stage = "rpc";
      logImport("RPC import_connection starting", {
        protocol,
        rpcStarted: true,
      });
      const response = await importConnection(
        protocol,
        filePath,
        importName,
        username,
        password,
        passphrase,
      );
      rpcReturned = true;
      logImport(
        response.success
          ? "RPC import_connection returned success"
          : "RPC import_connection returned failure",
        {
          protocol,
          code: importErrorCode(response.code),
          rpcStarted: true,
        },
      );
      checkImportResponse(response);
      if (!response.connection?.id) {
        throw new DisplayedRpcError(
          unexpectedImportError(language, "IMPORT_RPC_FAILED"),
        );
      }
      stage = "refresh";
      logImport("refresh after import started", { protocol, rpcStarted: true });
      const refreshed = await getSnapshot();
      checkImportResponse(refreshed);
      logImport("fresh snapshot", {
        connections: refreshed.connections.length,
        rpcStarted: true,
      });
      if (!snapshotContainsConnection(refreshed, response.connection.id)) {
        throw new DisplayedRpcError(
          unexpectedImportError(language, "IMPORT_NOT_VISIBLE"),
        );
      }
      stage = "complete";
      setSnapshot(refreshed);
      setPage("main");
      setUsername("");
      setPassword("");
      setPassphrase("");
      logImport("import completed", { protocol, rpcStarted: true });
      importToast(t(language, "imported"));
    } catch (reason: unknown) {
      if (stage === "rpc" && !rpcReturned)
        logImport("RPC import_connection returned failure", {
          protocol,
          code: "IMPORT_RPC_FAILED",
          errorKind: importErrorKind(reason),
          rpcStarted: true,
        });
      const code =
        stage === "preflight"
          ? "IMPORT_FRONTEND_FAILED"
          : stage === "refresh"
            ? "IMPORT_REFRESH_FAILED"
            : "IMPORT_RPC_FAILED";
      logImport("import failed", {
        protocol,
        stage,
        code,
        errorKind: importErrorKind(reason),
        rpcStarted: stage !== "preflight",
      });
      const message =
        reason instanceof DisplayedRpcError
          ? reason.message
          : unexpectedImportError(language, code);
      setError(message);
      importToast(message, true);
    } finally {
      importInFlight.current = false;
      setBusy(false);
    }
  };

  const openDiagnostics = async (connection: Connection) => {
    if (operationInFlight.current) return;
    operationInFlight.current = true;
    setSelected(connection);
    setDiagnostics(null);
    setPage("diagnostics");
    setBusy(true);
    setError("");
    try {
      const response = await getDiagnostics(connection.id);
      ensureSuccess(response, language);
      setDiagnostics(response.diagnostics);
      if (response.diagnostics.external_ip_checks)
        setIpChecks(response.diagnostics.external_ip_checks);
    } catch (reason: unknown) {
      setError(
        reason instanceof DisplayedRpcError
          ? reason.message
          : "DIAGNOSTICS_RPC_FAILED",
      );
    } finally {
      operationInFlight.current = false;
      setBusy(false);
    }
  };

  const measureExternalIp = async () => {
    if (operationInFlight.current) return;
    operationInFlight.current = true;
    setBusy(true);
    setError("");
    try {
      const response = await checkExternalIp();
      ensureSuccess(response, language);
      if (!response.external_ip_checks) throw new Error("Invalid IP response");
      setIpChecks(response.external_ip_checks);
    } catch (reason: unknown) {
      setError(
        reason instanceof DisplayedRpcError
          ? reason.message
          : "EXTERNAL_IP_RPC_FAILED",
      );
    } finally {
      operationInFlight.current = false;
      setBusy(false);
    }
  };

  if (!snapshot) {
    return (
      <PanelSection title={t(language, "loading")}>
        {error ? <div role="alert">{error}</div> : null}
      </PanelSection>
    );
  }

  const visibleError =
    error ||
    (snapshot.runtime.error_code
      ? displayRpcError(language, { code: snapshot.runtime.error_code })
      : "");
  const errorView = visibleError ? (
    <PanelSectionRow>
      <div
        role="alert"
        style={{
          ...cardStyle,
          color: "#ff9d9d",
          overflowWrap: "anywhere",
          whiteSpace: "pre-wrap",
        }}
      >
        {visibleError}
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
              <ButtonItem
                layout="below"
                disabled={busy}
                onClick={() => void beginImport(item)}
              >
                {protocolLabel(item)}
              </ButtonItem>
            </PanelSectionRow>
          ))}
          <PanelSectionRow>
            <ButtonItem layout="below" onClick={() => setPage("main")}>
              {t(language, "back")}
            </ButtonItem>
          </PanelSectionRow>
          <ImportDebugLog language={language} />
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
              onClick={() => {
                logImport("import button pressed");
                void importSelected();
              }}
            >
              {t(language, "import")}
            </ButtonItem>
          </PanelSectionRow>
          <PanelSectionRow>
            {busy
              ? t(language, "importWorking")
              : !name.trim()
                ? t(language, "importNameRequired")
                : null}
          </PanelSectionRow>
          <PanelSectionRow>
            <ButtonItem
              layout="below"
              disabled={busy}
              onClick={() => setPage("main")}
            >
              {t(language, "cancel")}
            </ButtonItem>
          </PanelSectionRow>
          <ImportDebugLog language={language} />
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
          <PanelSectionRow>
            <div style={{ ...cardStyle, overflowWrap: "anywhere" }}>
              <strong>{t(language, "deviceExternalIp")}</strong>
              <p style={{ fontSize: 12 }}>{t(language, "ipPrivacy")}</p>
              {(["before", "after"] as const).map((slot) => {
                const sample = ipChecks[slot];
                return (
                  <div key={slot} style={{ marginBottom: 10 }}>
                    <div>
                      {t(language, slot === "before" ? "ipBefore" : "ipAfter")}
                    </div>
                    <strong>{sample?.ip ?? "—"}</strong>
                    {sample ? (
                      <div style={{ fontSize: 12 }}>
                        {sample.connection_name ? (
                          <div>{sample.connection_name}</div>
                        ) : null}
                        <div>
                          {new Date(sample.checked_at).toLocaleString(language)}
                        </div>
                        <div>{sample.provider}</div>
                      </div>
                    ) : null}
                  </div>
                );
              })}
              {ipChecks.before && ipChecks.after ? (
                <div>
                  {t(
                    language,
                    ipChecks.before.ip === ipChecks.after.ip
                      ? "ipUnchanged"
                      : "ipChanged",
                  )}
                </div>
              ) : null}
              <p style={{ fontSize: 12 }}>{t(language, "ipRoutingNote")}</p>
            </div>
          </PanelSectionRow>
          <PanelSectionRow>
            <ButtonItem
              layout="below"
              disabled={busy}
              onClick={() => void measureExternalIp()}
            >
              <span
                style={{
                  display: "block",
                  whiteSpace: "normal",
                  overflowWrap: "anywhere",
                }}
              >
                {t(language, "checkExternalIp")}
              </span>
            </ButtonItem>
          </PanelSectionRow>
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
          const transitional = ["CONNECTING", "DISCONNECTING"].includes(status);
          const recoveringOn =
            snapshot.runtime.connection_id === connection.id &&
            snapshot.settings.desired_state === "ON" &&
            ["RECOVERING", "ERROR"].includes(status);
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
                  checked={active || recoveringOn}
                  disabled={
                    busy || transitional || Boolean(connection.import_error)
                  }
                  onChange={(value) =>
                    void run(() =>
                      value ? connect(connection.id) : disconnect(),
                    )
                  }
                />
                <div
                  style={{
                    display: "grid",
                    gridTemplateColumns: "minmax(0, 1fr)",
                    gap: 6,
                    marginTop: 6,
                  }}
                >
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
        <ImportDebugLog language={language} />
      </PanelSection>
    </div>
  );
}

export default definePlugin(() => ({
  name: "V-Deck",
  // Decky removes content when QAM is hidden unless this is set. Keep the
  // pending file-picker promise and validated form attached to the same instance.
  alwaysRender: true,
  titleView: <div className={staticClasses.Title}>V-Deck</div>,
  content: <VDeckContent />,
  icon: <FaNetworkWired />,
  onDismount() {},
}));
