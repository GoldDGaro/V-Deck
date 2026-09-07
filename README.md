# V-Deck 0.1.0

V-Deck — плагин Decky Loader для управления VPN на Steam Deck прямо из Gaming Mode: профили AmneziaWG, WireGuard и OpenVPN, автоподключение, Kill Switch и диагностика. VPN-сервер и конфигурацию предоставляет пользователь; подписка или VPN-сервис в проект не входят.

[English version](#english)

> [!IMPORTANT]
> Публичный предварительный релиз, не гарантия совместимости или отсутствия утечек. На физическом Steam Deck пользователь подтвердил AmneziaWG `.conf`/`.vpn`, подключение и доступ к игровому серверу, пинг, RU/EN, исправленную раскладку кнопок, перезагрузку и выключение/включение Wi-Fi с автоподключением и KS. WireGuard и OpenVPN пока проверены только локально с имитацией сети. Последний TLS-фикс проверки внешнего IP ещё ждёт проверки на устройстве. Полная матрица: [статус проверки](VALIDATION.md).

[Скачать установочный ZIP](https://github.com/GoldDGaro/V-Deck/releases/tag/v0.1.0-preview.2) · [Инструкция пользователя](USER_GUIDE_RU.md) · [English user guide](USER_GUIDE_EN.md) · [История изменений](CHANGELOG.md)

Релизный тег `v0.1.0-preview.2` обозначает новую сборку версии плагина `0.1.0`; старый `v0.1.0` сохранён для истории. Устанавливайте ZIP из нового релиза.

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
3. В настройках Decky включите режим разработчика, откройте раздел Developer и выберите установку плагина из ZIP. Пошаговые действия: [инструкция](USER_GUIDE_RU.md).
4. Перезапустите Decky Loader и откройте V-Deck в Quick Access Menu.
5. Импортируйте свой рабочий профиль для контролируемого тестирования. Фикстуры из `tests/` синтетические и к серверу не подключаются. Для первого подключения оставьте KS выключенным.

Docker, Go, Python/pnpm для разработки и отдельная установка OpenVPN/WireGuard/AmneziaWG на Steam Deck не нужны: клиенты входят в ZIP, Python предоставляет Decky. Используются штатные сетевые средства SteamOS; другие Linux-дистрибутивы и изменённые системные сетевые стеки не гарантируются.

Плагин запрашивает флаг Decky `root`: без повышенных привилегий Linux не позволяет создавать туннельные интерфейсы, назначать маршруты, управлять `nftables` и настраивать DNS отдельного интерфейса. Подчёркнутый шаблонный флаг `_root` не включает повышенные права в Decky Loader.

## Основной сценарий

1. Нажмите «Добавить VPN», выберите протокол, затем файл `.conf`, `.vpn` или `.ovpn`.
2. Проверьте непустое имя подключения и нажмите «Импорт» — выбор файла сам по себе профиль не сохраняет.
3. При необходимости введите учётные данные OpenVPN; они хранятся отдельно от общих метаданных.
4. Включите подключение. V-Deck запускает backend, проверяет интерфейс, маршруты, DNS и трафик. При первом ручном Connect kill switch применяется после базовых проверок, при восстановлении — до них.
5. Откройте диагностику, чтобы проверить handshake, прохождение трафика, маршрутизацию и DNS.
6. Выключение вручную сохраняется и не отменяется автоматически после перезагрузки или смены сети.

V-Deck передаёт backend оба значения Decky File Picker (`path` и `realpath`) и использует первый реально доступный обычный файл. Ошибка выбора, parser или записи профиля всегда отображается в UI вместе со стабильным error code. Безопасная техническая последовательность импорта сохраняется в `DECKY_PLUGIN_LOG_DIR/vdeck.log` без ключей, паролей или содержимого конфигурации.

## Безопасность и приватность

### Проверка IP до и после VPN

На Linux IP-проверка явно использует системный CA-bundle (`/etc/ssl/cert.pem`, затем стандартные варианты в `/etc/ssl/certs/`), а не пути сборочного OpenSSL внутри Decky/PyInstaller. Проверка цепочки и hostname обязательна. Отсутствующее хранилище и отклонённый сертификат имеют отдельные коды `EXTERNAL_IP_CA_UNAVAILABLE` и `EXTERNAL_IP_TLS_FAILED`; технический лог содержит число CA и `verify_code`, но не содержимое ответа или сертификатов.

В диагностике нажмите «Проверить внешний IPv4» при выключенном V-Deck. Затем вернитесь к профилю, подключите VPN и повторите проверку. Оба снимка отображаются вместе со временем, источником ответа и названием активного профиля. При смене сети во время запроса результат отклоняется; старые снимки помечены как последние проверки, а не текущий непрерывный статус.

Используются стандартные Python `urllib.request`, `ssl`, `ipaddress` и HTTPS-сервисы [ipify](https://www.ipify.org/) (`api.ipify.org`), резервный `ipv4.icanhazip.com`. Сервис видит внешний адрес отправителя, но не получает конфигурацию, ключи или пароли. Проверка сертификата обязательна; редиректы и proxy из окружения отключены. Таймаут запроса — 4 секунды на сервис, ожидание RPC — до 10 секунд. Новые системные пакеты не нужны.

Запрос идёт по текущей системной маршрутизации: V-Deck не отключает VPN, не снимает Kill Switch и не создаёт обходной маршрут ради проверки. «V-Deck выключен» не означает, что выключены другие VPN. Сравнение IPv4 не доказывает отсутствие IPv6/DNS-утечек или полного обхода VPN при split tunnel. Снимки исчезают при перезапуске backend плагина.

Импортируемые файлы считаются недоверенными. V-Deck отклоняет OpenVPN command hooks, плагины, management-директивы, произвольные пути вывода, абсолютные пути, обход каталогов, неизвестные inline-блоки и выход через символические ссылки. Распаковка Amnezia `.vpn` ограничена по размеру.

Ресурсы удаляются только по собственным маркерам V-Deck:

- интерфейсы имеют вид `vdeck-xxxxxxxx`;
- маршруты помечаются protocol `186`;
- firewall находится только в таблице `inet vdeck` с проверяемым ownership comment; одноимённая чужая таблица не удаляется;
- DNS изменяется и возвращается отдельно для интерфейса V-Deck;
- процесс останавливается только при совпадении PID, исполняемого файла и времени старта процесса Linux.

Каталоги подключений создаются с правами `0700`, чувствительные файлы — `0600`. Секреты не передаются в аргументах процессов. Содержимое config не логируется; native stdout/stderr сохраняется только как распознанные диагностические фразы без произвольных значений. Исключения содержат тип/место/код, но не локальные переменные. IP-адреса маскируются в экспортируемых отчётах; технический лог может содержать пути и сетевые адреса. Телеметрии нет. Проверка внешнего IPv4 выполняется только отдельной кнопкой в диагностике. Открытие/обновление диагностики, экспорт отчёта и фоновый пинг не обращаются к сервисам определения IP. Полные результаты этой проверки хранятся только в памяти и не добавляются в лог или экспорт.

Подробнее: `SECURITY.md` и `THIRD_PARTY_NOTICES.md`.

## Kill switch

Kill switch необязателен, изначально отключён и включается только после явного принятия предупреждения. При первом ручном Connect он активируется после успешного соединения; при автоподключении/восстановлении правила заранее разрешают будущий собственный интерфейс, до проверок трафика. Он разрешает loopback, служебный DHCP/IPv6 ND, VPN-интерфейс и кешированные IP-адреса VPN-сервера, затем блокирует остальной исходящий IPv4/IPv6-трафик. При неожиданном обрыве правила остаются активными во время восстановления. Если IP hostname endpoint изменился, V-Deck кратковременно разрешает DNS только к обнаруженным системным DNS-серверам и сразу возвращает строгие правила. Ручное отключение удаляет таблицу только после проверки ownership marker V-Deck.

Если тестовая версия неожиданно заблокировала сеть, сначала выключите активное подключение в интерфейсе. Аварийная локальная команда из Desktop Mode:

```text
sudo nft delete table inet vdeck
```

Не очищайте глобальный набор правил `nftables`.

## Архитектура

`VPNManager` сериализует конечный автомат и гарантирует правило одного активного подключения. `BackendRegistry` содержит независимые реализации `AmneziaWGBackend`, `WireGuardBackend` и `OpenVPNBackend`. Хранилище, парсеры, идентификация процессов, маршруты, DNS, firewall, миграция, восстановление, диагностика, логирование и проверка бинарников разделены на модули в `py_modules/vdeck`.

Новый протокол может реализовать интерфейс `VPNBackend` и зарегистрироваться в одном месте без добавления условных веток по всему приложению. Frontend написан на TypeScript/React для Decky, backend — на Python с асинхронным RPC API.

## Сборка и проверки

Версии CI: Python 3.10.21, Node.js 22.23.2 и pnpm 9.15.9 (не pnpm latest). Docker используется только сопровождающими разработчиками и CI для воспроизводимой сборки Linux x86-64 компонентов; пользователю и Steam Deck он не нужен. Go 1.25.14, Zig 0.15.2, upstream tags/commits и release hashes закреплены в `backend/versions.json`.

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
python scripts/fetch_sources.py
python scripts/build_release.py
python scripts/verify_release.py ../outputs/V-Deck-v0.1.0.zip
python scripts/verify_source.py ../outputs/V-Deck-v0.1.0-source.zip
```

Релизный сборщик создаёт правильный корень `V-Deck/`, выставляет Unix executable mode для нативных файлов и формирует отдельный corresponding-source архив. CI повторяет backend/frontend-проверки, аудит ELF и верификацию упаковки.

## Ограничения тестовой версии

- Базовый AWG-сценарий и Wi-Fi OFF/ON проверены пользователем на одном Steam Deck; это не проверка всех устройств/серверов. Suspend/resume, roaming между разными сетями, IPv6/DNS-утечки и длительная стабильность остаются физическими тестами.
- OpenVPN требует явные локальные `route`/`redirect-gateway` и `dhcp-option DNS`. Маршруты создаёт и очищает V-Deck, OpenVPN запускается с `route-noexec`. Профили только с server-push routes/DNS пока не поддержаны и получают понятный error code до запуска процесса. Проверка на реальном сервере обязательна.
- WG `Table=off` и custom Table не поддерживаются: импорт явно отклоняет их, не меняя смысл профиля.
- OpenVPN с wolfSSL не поддерживает часть устаревших OpenSSL-профилей, особенно старые Blowfish-конфигурации. Рекомендуется AES.
- В версии 0.1.0 нет вставки `vpn://`; импортируйте экспортированный файл `.vpn`.
- Совместимость PolyForm Noncommercial с правилами публикации в Decky Store пока не подтверждена. Поддерживаемый канал тестовой установки — ZIP из GitHub Releases.

## Лицензия

Оригинальный код V-Deck распространяется по неизменённой **PolyForm Noncommercial License 1.0.0**. Лицензия разрешает использование, изменение и распространение в некоммерческих целях. Коммерческое использование требует отдельного разрешения правообладателя. Это source-available лицензия, а не OSI-approved open-source лицензия. Полный текст находится в `LICENSE`.

Встроенные сторонние исполняемые файлы и библиотеки сохраняют собственные лицензии MIT, GPL, LGPL, 0BSD и дополнительные исключения. Полный перечень и тексты: `THIRD_PARTY_NOTICES.md`, каталог `licenses/` и corresponding-source ZIP в каждом бинарном релизе.

---

<a id="english"></a>

## English

V-Deck is a Decky Loader VPN manager for Steam Deck Gaming Mode: AmneziaWG, WireGuard and OpenVPN profiles, auto-connect, Kill Switch and diagnostics. Bring your own VPN server and configuration; no VPN service or subscription is included.

> [!IMPORTANT]
> Public preview, not a compatibility or leak-free guarantee. User feedback on a physical Steam Deck confirms AmneziaWG `.conf`/`.vpn`, connection and real game-server traffic, ping, RU/EN, corrected buttons, reboot and Wi-Fi OFF/ON with auto-connect and KS. WireGuard and OpenVPN have local mocked coverage only. The latest external-IP TLS fix still awaits device validation. See the [validation matrix](VALIDATION.md).

[Download installer](https://github.com/GoldDGaro/V-Deck/releases/tag/v0.1.0-preview.2) · [User guide](USER_GUIDE_EN.md) · [Инструкция на русском](USER_GUIDE_RU.md) · [Changelog](CHANGELOG.md)

Release tag `v0.1.0-preview.2` identifies the updated build of plugin version `0.1.0`; the old `v0.1.0` tag is preserved. Use the ZIP from the new release.

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
3. Enable developer mode in Decky settings, open Developer and choose ZIP plugin installation. See the [step-by-step guide](USER_GUIDE_EN.md).
4. Restart Decky Loader and open V-Deck from the Quick Access menu.
5. Import a working profile intended for controlled testing. Synthetic fixtures under `tests/` cannot connect to real servers. Leave KS off for the first connection.

No Docker, development Go/Python/pnpm or separate OpenVPN/WireGuard/AmneziaWG package installation is needed on the Deck: clients are bundled and Decky supplies Python. V-Deck uses stock SteamOS network utilities; other Linux distributions and modified network stacks are not guaranteed.

The plugin requests Decky's `root` flag because Linux tunnel interfaces, routes, `nftables`, and per-link DNS cannot be managed by the unprivileged `deck` user. The template placeholder `_root` does not enable elevated privileges in Decky Loader.

## Basic workflow

1. Select Add VPN, choose the protocol, then a `.conf`, `.vpn`, or `.ovpn` file.
2. Enter a non-empty connection name and press Import. Picking a file alone does not save a profile.
3. Enter OpenVPN credentials when required; they are stored separately from shared metadata.
4. Turn the connection on. V-Deck checks the backend, interface, routes, DNS and traffic. On initial manual Connect the kill switch follows basic checks; during recovery its rules are prepared before those checks.
5. Open diagnostics to inspect handshake, traffic proof, routing, and DNS.
6. Manual OFF persists and is not silently undone after a reboot or network change.

V-Deck passes both Decky File Picker values (`path` and `realpath`) to the backend and uses the first accessible regular file. Picker, parser, or storage failures are always shown in the UI with a stable error code. The sanitized technical import lifecycle is written to `DECKY_PLUGIN_LOG_DIR/vdeck.log` without keys, passwords, or configuration contents.

## Security and privacy

### Compare IP before and after VPN

On Linux the IP check explicitly loads the host CA bundle (`/etc/ssl/cert.pem`, then standard alternatives under `/etc/ssl/certs/`), not the frozen interpreter's build-time OpenSSL paths. Chain and hostname verification remain mandatory. Missing trust and rejected certificates return `EXTERNAL_IP_CA_UNAVAILABLE` and `EXTERNAL_IP_TLS_FAILED`; logs contain the CA count and numeric `verify_code`, never response or certificate contents.

In diagnostics, press "Check external IPv4 now" with V-Deck OFF, then connect and repeat. Both timestamped samples show their provider and the active profile name. Network changes during a request invalidate the result. Samples are historical measurements, not a continuous live status, and are cleared on plugin backend restart.

The implementation uses Python standard-library `urllib.request`, `ssl`, and `ipaddress`, querying [ipify](https://www.ipify.org/) (`api.ipify.org`) over HTTPS with `ipv4.icanhazip.com` as fallback. The service sees the requester's public address, never VPN configuration or credentials. TLS verification is mandatory; redirects and ambient proxies are disabled. Each provider has a 4-second timeout; the RPC waits up to 10 seconds. No new system packages are required.

The check follows current system routing without switching VPN off, bypassing Kill Switch, or adding routes. V-Deck OFF does not mean another VPN is off. An IPv4 comparison is not a complete IPv6/DNS leak test or proof of full-tunnel routing.

Every imported configuration is treated as hostile. V-Deck rejects OpenVPN command hooks, plugins, management directives, arbitrary output paths, absolute paths, traversal, unknown inline blocks, and symlink escapes. Native Amnezia `.vpn` decompression is size-bounded.

Cleanup is restricted to V-Deck ownership markers:

- interfaces match `vdeck-xxxxxxxx`;
- routes carry protocol marker `186`;
- firewall rules live only in `table inet vdeck` with a verified ownership comment; an unrelated same-name table is never deleted;
- DNS is changed and reverted per V-Deck interface;
- a process is stopped only when PID, executable, and Linux process start time still match.

Connection directories use mode `0700` and sensitive files use `0600`. Secrets are never placed in process arguments. Config contents are not logged; native stdout/stderr is reduced to recognized diagnostic phrases without arbitrary values. Exceptions include type/location/code, not locals. Exported reports mask IP addresses; technical logs may contain paths and network addresses. V-Deck collects no telemetry. External IPv4 requests require a dedicated diagnostics button. Opening/refreshing diagnostics, exporting a report and background ping do not contact IP services. Full samples are held in memory only and are not added to logs or exports.

See `SECURITY.md` and `THIRD_PARTY_NOTICES.md` for more detail.

## Kill switch

The kill switch is optional, initially disabled, and requires explicit acknowledgement. On the initial manual Connect it activates after a successful connection; during auto-connect/recovery it permits the upcoming owned tunnel before traffic checks. It permits loopback, DHCP/IPv6 ND control traffic, the VPN interface, and cached VPN endpoint IPs, then rejects other IPv4 and IPv6 output. On unexpected tunnel loss, it remains active while recovery runs. If a hostname endpoint changes address, V-Deck briefly permits DNS only to detected system DNS servers and immediately restores the strict rules. Manual OFF removes the table only after verifying V-Deck's ownership marker.

If this test build unexpectedly blocks networking, first turn the active connection off in the UI. Last-resort local recovery from Desktop Mode:

```text
sudo nft delete table inet vdeck
```

Do not flush the global `nftables` ruleset.

## Architecture

`VPNManager` serializes the state machine and enforces the single-active rule. `BackendRegistry` holds independent `AmneziaWGBackend`, `WireGuardBackend`, and `OpenVPNBackend` implementations. Storage, parsers, process identity, routes, DNS, firewall, migration, recovery, diagnostics, logging, and binary validation are isolated modules under `py_modules/vdeck`.

A future protocol can implement `VPNBackend` and register in one place without adding protocol branches across the application. The Decky frontend uses TypeScript/React; the asynchronous RPC backend uses Python.

## Build and verification

CI uses Python 3.10.21, Node.js 22.23.2 and pnpm 9.15.9 (not pnpm latest). Docker is used only by maintainers and CI for reproducible Linux x86-64 component builds; users and Steam Deck do not need it. Go 1.25.14, Zig 0.15.2, upstream tags/commits, and release hashes are pinned in `backend/versions.json`.

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
python scripts/fetch_sources.py
python scripts/build_release.py
python scripts/verify_release.py ../outputs/V-Deck-v0.1.0.zip
python scripts/verify_source.py ../outputs/V-Deck-v0.1.0-source.zip
```

The release builder creates the required `V-Deck/` ZIP root, assigns Unix executable mode to native files, and emits a separate corresponding-source archive. CI repeats backend/frontend checks, ELF auditing, and package verification.

## Test-release limitations

- Basic AWG and Wi-Fi OFF/ON were user-tested on one Deck, not every device/server. Suspend/resume, roaming between different networks, IPv6/DNS leak testing and long-term stability still need physical validation.
- OpenVPN requires explicit local `route`/`redirect-gateway` and `dhcp-option DNS` directives. V-Deck owns route creation/cleanup and starts OpenVPN with `route-noexec`. Server-push-only routes/DNS are currently unsupported and return an explicit error before spawning the process. Live-server verification is still required.
- WG `Table=off` and custom Table values are rejected explicitly instead of silently changing profile semantics.
- OpenVPN built with wolfSSL does not support every legacy OpenSSL profile, especially old Blowfish configurations. Upgrade profiles to AES.
- Version 0.1.0 does not provide a `vpn://` paste UI; import the exported `.vpn` file.
- Decky Store acceptance of PolyForm Noncommercial has not been confirmed. The supported test distribution method is the GitHub release ZIP.

## License

Original V-Deck code is distributed under the unmodified **PolyForm Noncommercial License 1.0.0**. It permits use, modification, and distribution for noncommercial purposes. Commercial use requires separate permission from the licensor. This is a source-available license, not an OSI-approved open-source license. See `LICENSE` for the complete terms.

Bundled third-party executables and libraries retain their MIT, GPL, LGPL, 0BSD, and additional exception terms. See `THIRD_PARTY_NOTICES.md`, `licenses/`, and the corresponding-source ZIP attached to every binary release.
