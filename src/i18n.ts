export type Language = "ru" | "en";

const translations = {
  en: {
    title: "V-Deck",
    addVpn: "Add VPN",
    settings: "Settings",
    back: "Back",
    cancel: "Cancel",
    save: "Save",
    confirm: "Confirm",
    delete: "Delete",
    rename: "Rename",
    diagnostics: "Diagnostics",
    refresh: "Refresh",
    exportReport: "Export diagnostic report",
    noConnections: "Add a VPN configuration to get started.",
    chooseProtocol: "Choose protocol",
    chooseFile: "Choose configuration file",
    connectionName: "Connection name",
    username: "Username",
    password: "Password",
    passphrase: "Private-key passphrase",
    import: "Import",
    imported: "VPN imported",
    importFailed: "Failed to import configuration",
    importDebugLog: "Import debug log",
    importWorking: "Import in progress…",
    importNameRequired: "Enter a connection name to enable Import.",
    fileNotAccessible: "The selected configuration file is not accessible",
    reportSaved: "Diagnostic report saved",
    autoConnect: "Auto-connect",
    killSwitch: "Kill Switch",
    language: "Language",
    automatic: "Automatic",
    russian: "Русский",
    english: "English",
    killWarning:
      "If an established VPN connection is unexpectedly lost, direct internet access stays blocked until recovery or manual VPN OFF.",
    deleteConfirm: "Delete this connection and its saved credentials?",
    disconnected: "Disconnected",
    connecting: "Connecting…",
    connected: "Connected",
    disconnecting: "Disconnecting…",
    recovering: "Recovering…",
    error: "Connection error",
    ping: "Ping",
    session: "Session",
    received: "Received",
    sent: "Sent",
    tunnel: "Tunnel",
    handshake_state: "Handshake / State",
    traffic: "Data transfer",
    routing: "Routing",
    internet: "Internet through VPN",
    ipv4: "IPv4",
    ipv6: "IPv6",
    external_ip: "External IP",
    deviceExternalIp: "Device external IPv4",
    checkExternalIp: "Check external IPv4 now",
    ipBefore: "V-Deck OFF · last check",
    ipAfter: "V-Deck connected · last check",
    ipChanged: "The measured IPv4 addresses differ.",
    ipUnchanged: "The measured IPv4 addresses are the same.",
    ipPrivacy:
      "Only on click: HTTPS to ipify, with icanhazip as fallback. The service sees your public IP; VPN keys and configuration are never sent. Samples stay in memory until the plugin restarts.",
    ipRoutingNote:
      "Check once with V-Deck OFF, then connect and check again. Uses current system routing; does not bypass Kill Switch. Another VPN or split routing may affect the result. This IPv4 comparison is not a full leak test.",
    ipCheckFailed: "Could not check the external IP",
    ipTlsFailed:
      "Could not verify the IP service's TLS certificate. Check device time and the technical log.",
    ipCaUnavailable: "Could not load the system's trusted CA certificates.",
    ipNetworkChanged: "The network changed during the check. Try again.",
    ipVpnBusy:
      "Wait for VPN recovery or manually turn V-Deck off before checking.",
    loading: "Loading…",
    validationFailed: "Configuration validation failed",
    migrationFailed: "Migration failed",
    genericError: "Operation failed",
    invalidConfig: "The VPN configuration is invalid or unsupported",
    credentialsRequired: "VPN credentials are required",
    authenticationFailed: "VPN authentication failed",
    handshakeTimeout: "The VPN server did not complete a handshake",
    operationInProgress: "Another VPN operation is still in progress",
    networkSetupFailed: "VPN network setup failed",
    copiedPath: "Saved to",
  },
  ru: {
    title: "V-Deck",
    addVpn: "Добавить VPN",
    settings: "Настройки",
    back: "Назад",
    cancel: "Отмена",
    save: "Сохранить",
    confirm: "Подтвердить",
    delete: "Удалить",
    rename: "Переименовать",
    diagnostics: "Диагностика",
    refresh: "Обновить",
    exportReport: "Экспортировать отчёт",
    noConnections: "Добавьте VPN-конфигурацию, чтобы начать.",
    chooseProtocol: "Выберите протокол",
    chooseFile: "Выбрать файл конфигурации",
    connectionName: "Название подключения",
    username: "Имя пользователя",
    password: "Пароль",
    passphrase: "Пароль приватного ключа",
    import: "Импортировать",
    imported: "VPN импортирован",
    importFailed: "Не удалось импортировать конфигурацию",
    importDebugLog: "Журнал импорта",
    importWorking: "Выполняется импорт…",
    importNameRequired:
      "Введите название подключения, чтобы включить кнопку импорта.",
    fileNotAccessible: "Выбранный файл конфигурации недоступен",
    reportSaved: "Диагностический отчёт сохранён",
    autoConnect: "Автоподключение",
    killSwitch: "Kill Switch",
    language: "Язык",
    automatic: "Автоматически",
    russian: "Русский",
    english: "English",
    killWarning:
      "Если уже установленное VPN-соединение неожиданно пропадёт, прямой интернет останется заблокирован до восстановления VPN или ручного выключения.",
    deleteConfirm: "Удалить подключение и сохранённые credentials?",
    disconnected: "Отключено",
    connecting: "Подключение…",
    connected: "Подключено",
    disconnecting: "Отключение…",
    recovering: "Восстановление…",
    error: "Ошибка подключения",
    ping: "Пинг",
    session: "Сессия",
    received: "Получено",
    sent: "Отправлено",
    tunnel: "Туннель",
    handshake_state: "Handshake / состояние",
    traffic: "Передача данных",
    routing: "Маршрутизация",
    internet: "Интернет через VPN",
    ipv4: "IPv4",
    ipv6: "IPv6",
    external_ip: "Внешний IP",
    deviceExternalIp: "Внешний IPv4 устройства",
    checkExternalIp: "Проверить внешний IPv4",
    ipBefore: "V-Deck выключен · последняя проверка",
    ipAfter: "V-Deck подключён · последняя проверка",
    ipChanged: "Измеренные IPv4-адреса различаются.",
    ipUnchanged: "Измеренные IPv4-адреса совпадают.",
    ipPrivacy:
      "Только по нажатию: HTTPS-запрос к ipify, при ошибке — к icanhazip. Сервис видит ваш внешний IP; ключи и конфигурация VPN не отправляются. Результаты хранятся в памяти до перезапуска плагина.",
    ipRoutingNote:
      "Проверьте IP с выключенным V-Deck, затем подключитесь и повторите проверку. Используется текущий системный маршрут без обхода Kill Switch. Другой VPN или split tunnel могут влиять на результат. Сравнение IPv4 не заменяет проверку всех утечек.",
    ipCheckFailed: "Не удалось проверить внешний IP",
    ipTlsFailed:
      "Не удалось проверить TLS-сертификат сервиса IP. Проверьте время устройства и технический лог.",
    ipCaUnavailable:
      "Не удалось загрузить системные доверенные CA-сертификаты.",
    ipNetworkChanged: "Во время проверки сеть изменилась. Повторите запрос.",
    ipVpnBusy:
      "Дождитесь восстановления VPN или вручную выключите V-Deck перед проверкой.",
    loading: "Загрузка…",
    validationFailed: "Конфигурация не прошла проверку",
    migrationFailed: "Ошибка миграции",
    genericError: "Операция не выполнена",
    invalidConfig: "Конфигурация VPN некорректна или не поддерживается",
    credentialsRequired: "Требуются учётные данные VPN",
    authenticationFailed: "Ошибка аутентификации VPN",
    handshakeTimeout: "VPN-сервер не завершил handshake",
    operationInProgress: "Другая VPN-операция ещё выполняется",
    networkSetupFailed: "Не удалось настроить сеть VPN",
    copiedPath: "Сохранено в",
  },
} as const;

export type TranslationKey = keyof (typeof translations)["en"];

export function t(language: Language, key: TranslationKey): string {
  return translations[language][key];
}

const stableErrorKeys: Record<string, TranslationKey> = {
  EXTERNAL_IP_UNAVAILABLE: "ipCheckFailed",
  EXTERNAL_IP_TLS_FAILED: "ipTlsFailed",
  EXTERNAL_IP_CA_UNAVAILABLE: "ipCaUnavailable",
  EXTERNAL_IP_TIMEOUT: "ipCheckFailed",
  EXTERNAL_IP_NETWORK_CHANGED: "ipNetworkChanged",
  EXTERNAL_IP_VPN_BUSY: "ipVpnBusy",
  CREDENTIALS_REQUIRED: "credentialsRequired",
  PASSPHRASE_REQUIRED: "credentialsRequired",
  OPENVPN_AUTH_FAILED: "authenticationFailed",
  PASSPHRASE_INVALID: "authenticationFailed",
  HANDSHAKE_TIMEOUT: "handshakeTimeout",
  OPERATION_IN_PROGRESS: "operationInProgress",
  DNS_UNAVAILABLE: "networkSetupFailed",
  ENDPOINT_RESOLVE_FAILED: "networkSetupFailed",
  INTERFACE_CREATE_FAILED: "networkSetupFailed",
  COMMAND_FAILED: "networkSetupFailed",
  CONFIG_FILE_NOT_ACCESSIBLE: "fileNotAccessible",
};

export function rpcErrorMessage(
  language: Language,
  code?: string,
  fallback?: string,
): string {
  let key = code ? stableErrorKeys[code] : undefined;
  if (
    !key &&
    code &&
    (code.startsWith("CONFIG_") || code.startsWith("AMNEZIA_"))
  ) {
    key = "invalidConfig";
  }
  return key ? t(language, key) : fallback || t(language, "genericError");
}

export function displayRpcError(
  language: Language,
  response: { code?: string; message?: string },
  heading: TranslationKey = "genericError",
): string {
  const code = response.code || "RPC_FAILED";
  const title = t(language, heading);
  const detail = rpcErrorMessage(language, code, response.message);
  return [title, code, detail]
    .filter((value, index, values) => value && values.indexOf(value) === index)
    .join("\n");
}
