# V-Deck 0.1.0

V-Deck — приватно тестируемый плагин Decky Loader для управления AmneziaWG, WireGuard и OpenVPN на Steam Deck прямо из Gaming Mode.

[English version](#english)

> [!IMPORTANT]
> Автоматическая сборка, статический анализ и тесты проходят. Версия 0.1.0 пока является тестовой: работа на физическом Steam Deck, реальные VPN-серверы, suspend/resume и смена сетей должны быть проверены по `MANUAL_TESTS_STEAM_DECK.md` до повседневного использования.

## Возможности

- Импорт AmneziaWG `.conf`, включая актуальные параметры AWG 3.1 и совместимые старые поля.
- Импорт нативных экспортов Amnezia `.vpn` с контейнерами `amnezia-awg` и `amnezia-awg2`.
- Импорт стандартных конфигураций WireGuard `.conf`.
- Импорт OpenVPN `.ovpn` со встроенными сертификатами и ключами либо с безопасно скопированными относительными файлами.
- Поддержка логина/пароля OpenVPN и парольных приватных ключей.
- Подключение, отключение и переключение профилей из меню быстрого доступа SteamOS.
- Только одно активное подключение: при переключении профиль A полностью останавливается до запуска профиля B.
- Сохранение желаемого состояния, автоподключение, повторные попытки и восстановление после неожиданного обрыва.
- Управление собственными интерфейсами, маршрутами, DNS и процессами без глобальной очистки сетевых настроек системы.
- Опциональный kill switch для IPv4 и IPv6, выключенный по умолчанию и требующий отдельного подтверждения.
- Диагностика туннеля, маршрутов, DNS, handshake, трафика, внешнего IP и состояния kill switch.
- Экспорт обезличенного диагностического отчёта без приватных ключей, паролей и полного публичного IP.
- Интерфейс и стабильные сообщения об ошибках на русском и английском языках.

## Поддерживаемые компоненты

| Компонент | Версия в 0.1.0 | Назначение |
| --- | --- | --- |
| AmneziaWG Go | 3.1.20260828 | userspace-туннель AmneziaWG |
| `awg` | 3.1.20260812 | конфигурация и состояние AmneziaWG |
| WireGuard Go | 0.0.20250522 | userspace-туннель WireGuard |
| `wg` | 1.0.20260223 | конфигурация и состояние WireGuard |
| OpenVPN | 2.7.6 + wolfSSL 5.9.2 | OpenVPN-клиент |

Все пять исполняемых файлов в релизе собраны как статические ELF64 x86-64 без динамического загрузчика. Их закреплённые исходные версии, коммиты и SHA-256 находятся в `backend/versions.json`.

## Установка

1. Установите актуальную стабильную версию Decky Loader.
2. На странице Releases скачайте `V-Deck-v0.1.0.zip`. Не используйте автоматически созданный GitHub архив исходников как установочный файл.
3. Включите режим разработчика Decky и установите плагин из ZIP. Альтернативно распакуйте верхнюю папку `V-Deck` в каталог плагинов Decky.
4. Перезапустите Decky Loader и откройте V-Deck в Quick Access Menu.
5. Импортируйте тестовый профиль без реальных секретов либо профиль, предназначенный для контролируемого тестирования.

Плагин запрашивает флаг Decky `root`: без повышенных привилегий Linux не позволяет создавать туннельные интерфейсы, назначать маршруты, управлять `nftables` и настраивать DNS отдельного интерфейса. Подчёркнутый шаблонный флаг `_root` не включает повышенные права в Decky Loader.

## Основной сценарий

1. Нажмите импорт и выберите `.conf`, `.vpn` или `.ovpn`.
2. Проверьте определённый протокол и имя подключения.
3. При необходимости введите учётные данные OpenVPN; они хранятся отдельно от общих метаданных.
4. Включите подключение. V-Deck запускает backend, проверяет интерфейс и маршруты, применяет DNS и только после успешного соединения может активировать kill switch.
5. Откройте диагностику, чтобы проверить handshake, прохождение трафика, маршрутизацию и DNS.
6. Выключение вручную сохраняется и не отменяется автоматически после перезагрузки или смены сети.

V-Deck передаёт backend оба значения Decky File Picker (`path` и `realpath`) и использует первый реально доступный обычный файл. Ошибка выбора, parser или записи профиля всегда отображается в UI вместе со стабильным error code. Безопасная техническая последовательность импорта сохраняется в `DECKY_PLUGIN_LOG_DIR/vdeck.log` без ключей, паролей или содержимого конфигурации.

## Безопасность и приватность

Импортируемые файлы считаются недоверенными. V-Deck отклоняет OpenVPN command hooks, плагины, management-директивы, произвольные пути вывода, абсолютные пути, обход каталогов, неизвестные inline-блоки и выход через символические ссылки. Распаковка Amnezia `.vpn` ограничена по размеру.

Ресурсы удаляются только по собственным маркерам V-Deck:

- интерфейсы имеют вид `vdeck-xxxxxxxx`;
- маршруты помечаются protocol `186`;
- firewall находится только в таблице `inet vdeck` с проверяемым ownership comment; одноимённая чужая таблица не удаляется;
- DNS изменяется и возвращается отдельно для интерфейса V-Deck;
- процесс останавливается только при совпадении PID, исполняемого файла и времени старта процесса Linux.

Каталоги подключений создаются с правами `0700`, чувствительные файлы — `0600`. Секреты не передаются в аргументах процессов. Логи и отчёты удаляют ключи WireGuard/AmneziaWG, пароли, токены, сертификаты, приватные ключи и маскируют IP-адреса. Телеметрии нет. Запрос внешнего IP выполняется только при ручном обновлении или экспорте диагностики.

Подробнее: `SECURITY.md` и `THIRD_PARTY_NOTICES.md`.

## Kill switch

Kill switch необязателен, изначально отключён и включается только после явного принятия предупреждения. Он активируется после первого успешного соединения, разрешает loopback, established-трафик, VPN-интерфейс и кешированные IP-адреса VPN-сервера, затем блокирует остальной исходящий IPv4/IPv6-трафик. При неожиданном обрыве правила остаются активными во время восстановления. Если IP hostname endpoint изменился, V-Deck кратковременно разрешает DNS только к обнаруженным системным DNS-серверам и сразу возвращает строгие правила. Ручное отключение удаляет таблицу только после проверки ownership marker V-Deck.

Если тестовая версия неожиданно заблокировала сеть, сначала выключите активное подключение в интерфейсе. Аварийная локальная команда из Desktop Mode:

```text
sudo nft delete table inet vdeck
```

Не очищайте глобальный набор правил `nftables`.

## Архитектура

`VPNManager` сериализует конечный автомат и гарантирует правило одного активного подключения. `BackendRegistry` содержит независимые реализации `AmneziaWGBackend`, `WireGuardBackend` и `OpenVPNBackend`. Хранилище, парсеры, идентификация процессов, маршруты, DNS, firewall, миграция, восстановление, диагностика, логирование и проверка бинарников разделены на модули в `py_modules/vdeck`.

Новый протокол может реализовать интерфейс `VPNBackend` и зарегистрироваться в одном месте без добавления условных веток по всему приложению. Frontend написан на TypeScript/React для Decky, backend — на Python с асинхронным RPC API.

## Сборка и проверки

Для кода плагина требуются Python 3.10+, Node.js 20+ и pnpm 9+. Docker используется только сопровождающими разработчиками и CI для воспроизводимой сборки Linux x86-64 компонентов; пользователю и Steam Deck он не нужен. Go 1.25.14, Zig 0.15.2, upstream tags/commits и release hashes закреплены в `backend/versions.json`.

```text
PYTHONPATH=py_modules python -m unittest discover -s tests -v
python -m ruff check py_modules tests main.py scripts
python -m mypy py_modules main.py scripts
pnpm install --frozen-lockfile
pnpm format:check
pnpm lint
pnpm typecheck
pnpm test
pnpm build
docker build -f backend/Dockerfile --target binaries --output type=local,dest=release/native .
python scripts/elf_audit.py release/native/*
python scripts/elf_audit.py bin/amneziawg-go bin/awg bin/wireguard-go bin/wg bin/openvpn
python scripts/build_release.py
python scripts/verify_release.py ../outputs/V-Deck-v0.1.0.zip
python scripts/verify_source.py ../outputs/V-Deck-v0.1.0-source.zip
```

Релизный сборщик создаёт правильный корень `V-Deck/`, выставляет Unix executable mode для нативных файлов и формирует отдельный corresponding-source архив. CI повторяет backend/frontend-проверки, аудит ELF и верификацию упаковки.

## Ограничения тестовой версии

- Требуется ручная проверка интерфейса Gaming Mode, suspend/resume, roaming между Wi-Fi, IPv6-провайдеров и реальных VPN-серверов.
- DNS OpenVPN применяется для локальных `dhcp-option DNS`; параметры, приходящие только через server push, требуют проверки на устройстве.
- OpenVPN с wolfSSL не поддерживает часть устаревших OpenSSL-профилей, особенно старые Blowfish-конфигурации. Рекомендуется AES.
- В версии 0.1.0 нет вставки `vpn://`; импортируйте экспортированный файл `.vpn`.
- Совместимость PolyForm Noncommercial с правилами публикации в Decky Store пока не подтверждена. Поддерживаемый канал тестовой установки — ZIP из GitHub Releases.

## Лицензия

Оригинальный код V-Deck распространяется по неизменённой **PolyForm Noncommercial License 1.0.0**. Лицензия разрешает использование, изменение и распространение в некоммерческих целях. Коммерческое использование требует отдельного разрешения правообладателя. Это source-available лицензия, а не OSI-approved open-source лицензия. Полный текст находится в `LICENSE`.

Встроенные сторонние исполняемые файлы и библиотеки сохраняют собственные лицензии MIT, GPL, LGPL, 0BSD и дополнительные исключения. Полный перечень и тексты: `THIRD_PARTY_NOTICES.md`, каталог `licenses/` и corresponding-source ZIP в каждом бинарном релизе.

---

<a id="english"></a>

## English

V-Deck is a privately tested Decky Loader plugin for managing AmneziaWG, WireGuard, and OpenVPN on Steam Deck directly from Gaming Mode.

> [!IMPORTANT]
> Automated builds, static analysis, and tests pass. Version 0.1.0 is still a test release: physical Steam Deck behavior, real VPN servers, suspend/resume, and network roaming must be validated with `MANUAL_TESTS_STEAM_DECK.md` before everyday use.

## Features

- Imports AmneziaWG `.conf`, including current AWG 3.1 parameters and compatible legacy fields.
- Imports native Amnezia `.vpn` exports containing `amnezia-awg` or `amnezia-awg2` containers.
- Imports standard WireGuard `.conf` configurations.
- Imports OpenVPN `.ovpn` with inline certificates/keys or safely copied relative external files.
- Supports OpenVPN username/password authentication and encrypted private-key passphrases.
- Connects, disconnects, and switches profiles from the SteamOS Quick Access menu.
- Enforces one active connection: profile A is fully stopped before profile B starts.
- Persists desired state and provides auto-connect, retry, and unexpected-disconnection recovery.
- Manages only its own interfaces, routes, DNS, firewall rules, and processes; it never flushes global network state.
- Provides an optional IPv4/IPv6 kill switch, disabled by default and gated behind an explicit warning.
- Diagnoses tunnel state, routes, DNS, handshake, traffic, external IP, and kill-switch state.
- Exports sanitized diagnostic reports without private keys, passwords, or complete public IP addresses.
- Provides Russian and English UI text and stable localized error messages.

## Bundled components

| Component | Version in 0.1.0 | Purpose |
| --- | --- | --- |
| AmneziaWG Go | 3.1.20260828 | AmneziaWG userspace tunnel |
| `awg` | 3.1.20260812 | AmneziaWG configuration and state |
| WireGuard Go | 0.0.20250522 | WireGuard userspace tunnel |
| `wg` | 1.0.20260223 | WireGuard configuration and state |
| OpenVPN | 2.7.6 + wolfSSL 5.9.2 | OpenVPN client |

All five release executables are static x86-64 ELF64 files without a dynamic loader. Pinned source tags, commits, and SHA-256 hashes are recorded in `backend/versions.json`.

## Installation

1. Install a current stable Decky Loader release.
2. Download `V-Deck-v0.1.0.zip` from Releases. Do not use GitHub's automatically generated source archive as the installer.
3. Enable Decky developer mode and install the plugin ZIP. Alternatively, unpack its top-level `V-Deck` directory into Decky's plugins directory.
4. Restart Decky Loader and open V-Deck from the Quick Access menu.
5. Import a synthetic profile or one intended for controlled testing.

The plugin requests Decky's `root` flag because Linux tunnel interfaces, routes, `nftables`, and per-link DNS cannot be managed by the unprivileged `deck` user. The template placeholder `_root` does not enable elevated privileges in Decky Loader.

## Basic workflow

1. Select import and choose a `.conf`, `.vpn`, or `.ovpn` file.
2. Review the detected protocol and connection name.
3. Enter OpenVPN credentials when required; they are stored separately from shared metadata.
4. Turn the connection on. V-Deck starts the backend, verifies the interface and routes, applies DNS, and can activate the kill switch only after a successful connection.
5. Open diagnostics to inspect handshake, traffic proof, routing, and DNS.
6. Manual OFF persists and is not silently undone after a reboot or network change.

V-Deck passes both Decky File Picker values (`path` and `realpath`) to the backend and uses the first accessible regular file. Picker, parser, or storage failures are always shown in the UI with a stable error code. The sanitized technical import lifecycle is written to `DECKY_PLUGIN_LOG_DIR/vdeck.log` without keys, passwords, or configuration contents.

## Security and privacy

Every imported configuration is treated as hostile. V-Deck rejects OpenVPN command hooks, plugins, management directives, arbitrary output paths, absolute paths, traversal, unknown inline blocks, and symlink escapes. Native Amnezia `.vpn` decompression is size-bounded.

Cleanup is restricted to V-Deck ownership markers:

- interfaces match `vdeck-xxxxxxxx`;
- routes carry protocol marker `186`;
- firewall rules live only in `table inet vdeck` with a verified ownership comment; an unrelated same-name table is never deleted;
- DNS is changed and reverted per V-Deck interface;
- a process is stopped only when PID, executable, and Linux process start time still match.

Connection directories use mode `0700` and sensitive files use `0600`. Secrets are never placed in process arguments. Log and report sanitizers redact WireGuard/AmneziaWG keys, passwords, tokens, certificates, private keys, and mask IP addresses. V-Deck collects no telemetry. External-IP requests occur only when diagnostics are manually refreshed or exported.

See `SECURITY.md` and `THIRD_PARTY_NOTICES.md` for more detail.

## Kill switch

The kill switch is optional, initially disabled, and requires explicit acknowledgement. It activates after the first successful tunnel connection, permits loopback, established traffic, the VPN interface, and cached VPN endpoint IPs, then rejects other IPv4 and IPv6 output. On unexpected tunnel loss, it remains active while recovery runs. If a hostname endpoint changes address, V-Deck briefly permits DNS only to detected system DNS servers and immediately restores the strict rules. Manual OFF removes the table only after verifying V-Deck's ownership marker.

If this test build unexpectedly blocks networking, first turn the active connection off in the UI. Last-resort local recovery from Desktop Mode:

```text
sudo nft delete table inet vdeck
```

Do not flush the global `nftables` ruleset.

## Architecture

`VPNManager` serializes the state machine and enforces the single-active rule. `BackendRegistry` holds independent `AmneziaWGBackend`, `WireGuardBackend`, and `OpenVPNBackend` implementations. Storage, parsers, process identity, routes, DNS, firewall, migration, recovery, diagnostics, logging, and binary validation are isolated modules under `py_modules/vdeck`.

A future protocol can implement `VPNBackend` and register in one place without adding protocol branches across the application. The Decky frontend uses TypeScript/React; the asynchronous RPC backend uses Python.

## Build and verification

Plugin development requires Python 3.10+, Node.js 20+, and pnpm 9+. Docker is used only by maintainers and CI for reproducible Linux x86-64 component builds; users and Steam Deck do not need it. Go 1.25.14, Zig 0.15.2, upstream tags/commits, and release hashes are pinned in `backend/versions.json`.

```text
PYTHONPATH=py_modules python -m unittest discover -s tests -v
python -m ruff check py_modules tests main.py scripts
python -m mypy py_modules main.py scripts
pnpm install --frozen-lockfile
pnpm format:check
pnpm lint
pnpm typecheck
pnpm test
pnpm build
docker build -f backend/Dockerfile --target binaries --output type=local,dest=release/native .
python scripts/elf_audit.py release/native/*
python scripts/elf_audit.py bin/amneziawg-go bin/awg bin/wireguard-go bin/wg bin/openvpn
python scripts/build_release.py
python scripts/verify_release.py ../outputs/V-Deck-v0.1.0.zip
python scripts/verify_source.py ../outputs/V-Deck-v0.1.0-source.zip
```

The release builder creates the required `V-Deck/` ZIP root, assigns Unix executable mode to native files, and emits a separate corresponding-source archive. CI repeats backend/frontend checks, ELF auditing, and package verification.

## Test-release limitations

- Gaming Mode layout, suspend/resume, Wi-Fi roaming, IPv6-provider behavior, and live VPN compatibility still require physical-device validation.
- OpenVPN DNS is applied for local `dhcp-option DNS` directives. Options supplied only through server push require device testing.
- OpenVPN built with wolfSSL does not support every legacy OpenSSL profile, especially old Blowfish configurations. Upgrade profiles to AES.
- Version 0.1.0 does not provide a `vpn://` paste UI; import the exported `.vpn` file.
- Decky Store acceptance of PolyForm Noncommercial has not been confirmed. The supported test distribution method is the GitHub release ZIP.

## License

Original V-Deck code is distributed under the unmodified **PolyForm Noncommercial License 1.0.0**. It permits use, modification, and distribution for noncommercial purposes. Commercial use requires separate permission from the licensor. This is a source-available license, not an OSI-approved open-source license. See `LICENSE` for the complete terms.

Bundled third-party executables and libraries retain their MIT, GPL, LGPL, 0BSD, and additional exception terms. See `THIRD_PARTY_NOTICES.md`, `licenses/`, and the corresponding-source ZIP attached to every binary release.
