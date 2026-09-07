# V-Deck 0.1.0 — ручная приёмка на Steam Deck

Текущие подтверждённые результаты: [VALIDATION.md](VALIDATION.md). Это матрица для повторяемых проверок, не список уже пройденных физических тестов. Инструкция установки и использования: [USER_GUIDE_RU.md](USER_GUIDE_RU.md).

## Повторная проверка внешнего IPv4 после TLS-исправления

Установить свежий ZIP, открыть диагностику и проверить IPv4 сначала при выключенном V-Deck, затем после Connect. В `vdeck.log` ожидается `external IP TLS trust source=host cafile=... ca_count=...`, затем успешный запрос. Если ошибка повторится, сохранить строки `EXTERNAL_IP_...` и `verify_code`. Проверка TLS не отключается: неверное время устройства, недоверенная цепочка или HTTPS-перехват должны давать явную ошибку, а не принятие непроверенного ответа. Новая сборка не меняет уже прошедшие физическую проверку автозапуск/KS/recovery и раскладку кнопок.

Автоматические проверки не заменяют тесты на физическом Steam Deck. Используйте синтетические имена/адреса в отчётах и никогда не прикладывайте реальные ключи или пароли. Для каждого сбоя сохраните версию SteamOS, Decky, модель Deck, протокол, код ошибки V-Deck и санитизированный diagnostic report.

## Первая рабочая кандидатная сборка — 2026-09-03

### Повторная приёмка после физических тестов — 2026-09-06

Первоначально базовый AWG `.conf`/`.vpn` и игра работали, но автозапуск и recovery+KS падали. В последующем отчёте пользователь подтвердил перезагрузку и Wi-Fi OFF/ON с KS + автоподключением и исправленные кнопки. Полная матрица ниже всё ещё требует повторов; IP/TLS фикс ждёт физической проверки.

1. Установить новый локальный ZIP поверх плагина, сохранив профили. Проверить RU/EN: «Диагностика», «Переименовать», «Удалить» расположены друг под другом и читаемы как без фокуса, так и с ним.
2. При выключенном V-Deck открыть диагностику профиля → «Проверить внешний IPv4». Записать снимок «V-Deck выключен». Открытие диагностики само по себе не должно делать IP-запрос.
3. Вернуться, подключить AWG, проверить игру/сайты, снова открыть диагностику → проверить IPv4. Видны оба адреса, время, сервис и активный профиль; смена адреса не является полной проверкой утечек. Проверить ошибку без интернета и возможность повторить запрос. При RECOVERING/KS-блокировке проверка не снимает защиту.
4. С Auto-connect ON перезагрузить Deck при активном AWG, отдельно с KS OFF и ON. Ожидается автоматический переход к CONNECTED после появления Wi-Fi/маршрута без ручного Connect. Проверить запуск с Wi-Fi OFF и его включение спустя более двух минут.
5. С активным VPN и KS ON выключить/включить Wi-Fi. Ожидается восстановление, трафик/DNS и CONNECTED; в логе применение firewall с реальным `vdeck-*` предшествует HEALTH. Не должно быть цикла `Operation not permitted → VPN_TRAFFIC_UNCONFIRMED → RECOVERY_EXHAUSTED` из-за собственных правил.
6. Во время ожидания сети вручную выключить VPN, затем включить Wi-Fi: VPN остаётся OFF, обычный интернет возвращается. Проверить ручное переключение профиля во время ожидания автоподключения.
7. Повторить Disconnect/Connect, проверить DNS, отсутствие owned routes/interfaces/processes/nft после OFF. Совместимость VPN Deck проверять только при V-Deck OFF; при активном KS чужой VPN намеренно может блокироваться. Причина прежнего сбоя VPN Deck ещё не установлена.
8. Сохранить новый `vdeck.log` и время каждой операции. Не прикладывать конфигурации и секреты. WG kernel/userspace, OpenVPN, suspend/resume и полная IPv6/DNS leak-проверка остаются отдельной физической приёмкой.

### Дополнение независимого локального аудита — 2026-09-06

- Повторить весь сценарий AWG `.vpn`, AWG `.conf`, WG kernel и WG userspace: Import → Connect → CONNECTED → интернет/DNS → Disconnect → обычная сеть. Затем повторные циклы, переключение профилей, Wi-Fi OFF/ON и suspend/resume. Не считать mocked-тесты подтверждением работы SteamOS.
- На активном VPN включить/выключить Kill Switch. При ошибке включения прежнее значение должно сохраняться; после RECOVERY_EXHAUSTED выключение KS должно снимать его правила, а manual OFF — полностью завершать cleanup. Ошибка DNS cleanup не должна оставлять живой owned VPN-процесс.
- Проверить IPv4-only и dual-stack профили, hostname с A/AAAA, отсутствие `vdeck-*`, `vdns-*`, маршрутов proto 186 и собственных таблиц nft после Disconnect. Проверить прежние DNS и открытие обычных сайтов.
- OpenVPN в этой сборке требует явные `redirect-gateway def1`/туннельные `route` и `dhcp-option DNS` в клиентском профиле. Профиль только с server-push routes/DNS получает `OPENVPN_ROUTES_REQUIRED`/`DNS_CONFIGURATION_REQUIRED` до запуска процесса. Не добавляйте произвольный DNS: используйте настройки своего VPN-провайдера. Совместимость реального TLS, wolfSSL, сертификатов, паролей и маршрутов требует сервера и Steam Deck.
- `Table=off`/custom Table у WG теперь явно отклоняется, а не молча превращается в маршрутизацию V-Deck. Старые профили с неразрешённым DNS-шаблоном необходимо заново импортировать из оригинального `.vpn`.
- В `vdeck.log` проверять `stage`, `code`, `exception`, `exit_code`, `cleanup`. Вывод native-процессов сохраняется только как `stderr_summary` с распознанными диагностическими фразами; неизвестное содержимое обозначается `NATIVE_OUTPUT_WITHHELD`, не содержит ключей/паролей/config. Отдельный native log начинается заново при запуске; основной вращаемый `vdeck.log` сохраняет историю попыток.
- Диагностика неактивного профиля не должна показывать активный туннель другого профиля. Ошибка загрузки диагностики должна отображать код и оставлять Refresh доступным.

1. Установить новый ZIP и перезапустить V-Deck. Профили должны сохраниться. Если старый native `.vpn` профиль выдаёт `CONFIG_UNRESOLVED_TEMPLATE`, заново импортировать исходный `.vpn` через Add VPN: предыдущая версия не сохраняла `dns1/dns2`, поэтому безопасно восстановить их без исходного файла невозможно. Не нужно удалять весь каталог настроек.
2. При Kill Switch OFF проверить по очереди AWG `.vpn`, его эквивалентный `.conf` и WG: Connect → CONNECTED → работающие интернет и DNS → Disconnect → обычные интернет и DNS восстановлены. Повторить цикл и переключение профилей. WG выбирает kernel либо userspace по доступности; не отключать системные модули ради принудительного fallback.
3. После базового успеха повторить с Kill Switch ON, Wi-Fi off/on и Manual OFF во время recovery. OFF должен снять принадлежащие V-Deck ограничения и не запускать новый Connect.
4. Проверить отсутствие оставшихся PID, UAPI socket, `vdeck-*`/`vdns-*`, маршрутов proto 186 и собственных nft-таблиц после OFF. Чужие процессы/маршруты/таблицы не должны меняться. При `CLEANUP_PENDING` повторить Disconnect и приложить диагностику.
5. При сбое прислать только код и Export diagnostics/санитизированный журнал. Ожидаются `stage=VALIDATE/ENDPOINT/PROCESS/SETCONF/INTERFACE/ROUTE/DNS/FIREWALL/HEALTH`, `code`, `exception`, `exit_code`, безопасный traceback и результат cleanup. Ошибка библиотечного загрузчика — `COMMAND_LOADER_FAILED`, а не «служба неактивна».

Native `.vpn` с DNS-шаблонами использует только экспортированные `dns1/dns2`. Отсутствующий основной DNS даёт `AMNEZIA_DNS_MISSING`; произвольный публичный resolver не назначается. Для проверки этой сборки желательно заново импортировать тестовый `.vpn`, не перенося его прежний `runtime-info.json`.

## Текущая приёмка DNS/runtime — 2026-09-02

1. Установить новый локальный ZIP, перезапустить V-Deck через Decky; убедиться, что существующий профиль сохранился.
2. С Kill Switch OFF включить AWG; ожидание: CONNECTED, работающий интернет и DNS, профиль остаётся в списке.
3. Выключить и повторно включить AWG; затем проверить WireGuard-профиль. После OFF обычный интернет/DNS должны восстановиться.
4. Если базовый Connect работает: включить KS, кратко отключить/включить Wi-Fi, дождаться восстановления и нажать OFF, включая случай ERROR/RECOVERY_EXHAUSTED.
5. При любом сбое прислать code и Export diagnostics (либо санитизированный `vdeck.log`) от Connect до cleanup. Не присылать config/ключи/пароли.

Журнал содержит `network environment` (версии, DNS mode, службы, resolv.conf, tools, TUN, IPv6), `connect stage=...`, `DNS backend selected`, DNS command/exit_code/sanitized stdout/stderr, `routes applied`, `VPN traffic confirmed`, `DNS restored`, `profile audit` до/после. Только реальное удаление через UI отмечается `explicit delete_connection RPC`.

DNS strategy: активный systemd-resolved со stub resolver → per-link DNS и `~.`; NetworkManager `dns=default` → `save no` DNS-профиль на отдельном `vdns-*` dummy, отрицательный DNS priority, без default route. Это не VPN backend: пакеты к DNS идут по проверенным VPN-маршрутам. NM dnsmasq/dnsconfd, неуправляемый resolv.conf или несовместимый режим → `DNS_BACKEND_UNSUPPORTED`, без изменения системных файлов. NM удаляет собственный временный профиль при cleanup; журнал сохраняет UUID для восстановления после сбоя.

Для WG/AWG Connect требуется успешный ICMP либо TCP/443 probe внутри AllowedIPs (полный IPv4: 1.1.1.1; IPv6: 2606:4700:4700::1111), handshake и ожидаемые маршруты. При заданном DNS требуется ответ на DNS-запрос `example.com` через VPN-интерфейс. В сети, блокирующей оба probe, результат — явная ошибка, а не неподтверждённый Connected. Split-tunnel использует адрес внутри настроенного диапазона; отсутствие доступного probe нужно учитывать при приёмке.

Полная очистка также должна убирать `vdns-*` и принадлежащую V-Deck таблицу `inet vdeck_ipv6`. Docker и установка VPN-пакетов на Steam Deck не нужны. Доступ к штатным системным сетевым службам/утилитам проверяется во время работы; отсутствующие возможности не подменяются автоматической установкой пакетов.

Повторный локальный review: после включения KS трафик и DNS проверяются ещё раз, до CONNECTED; DNS проверяется и в периодическом health check. После RECOVERY_EXHAUSTED новое событие физического интерфейса запускает recovery, события `vdeck-*`/`vdns-*` его не запускают; Manual OFF остаётся окончательным. Монитор NetworkManager перезапускается после EOF с задержкой 5 секунд.

Если в профиле нет `DNS=`, плагин не назначает произвольный публичный resolver. Известный прямой системный resolver разрешён после проверки маршрута и ответа; для full-tunnel/KS запрос обязан идти через VPN. Local stub/неоднозначный NSS или маршрут вне VPN дают `DNS_CONFIGURATION_REQUIRED`: в таком случае нужен DNS из настроек вашего VPN-провайдера, доступный внутри AllowedIPs. Для явно заданного VPN DNS перекрытие с LAN компенсируется собственным host-route; совпадение DNS с endpoint даёт `DNS_ENDPOINT_CONFLICT`, а не маршрутизационную петлю.

Дополнительные маркеры журнала: `connect requested`, `profile loaded`, `backend selected`, `Kill Switch apply succeeded`, `VPN traffic confirmed ... firewall_active=True`, `CONNECTED`, `cleanup started`, `routes removed`, `interface removed`, `profile_still_exists=True`, `cleanup completed`. Ошибки команд содержат exit_code; вывод конфигурационных инструментов wg/awg намеренно скрыт, поскольку они могут печатать некорректный ключ без метки PrivateKey.

## 1. Установка, перезапуск и удаление

**Prerequisites:** Steam Deck LCD или OLED, актуальный стабильный Decky Loader, `V-Deck-v0.1.0.zip`.

**Steps:** установить ZIP; перезапустить Decky; перезагрузить Deck; удалить плагин; перезагрузить; установить снова.

**Expected result:** V-Deck появляется в Quick Access, не создаёт VPN сам по себе, переживает рестарт/ребут, удаление не оставляет `vdeck-*`, route proto 186 или `table inet vdeck`, повторная установка работает.

**Failure data to collect:** loader log, `ip link`, `ip route show proto 186`, `ip -6 route show proto 186`, `sudo nft list table inet vdeck`.

## 2. Gaming Mode UI и локализация

**Prerequisites:** LCD и/или OLED; RU и EN в настройках V-Deck; не менее 15 тестовых конфигураций, включая длинные имена.

**Steps:** открыть список, Add VPN, Diagnostics и Settings; прокрутить геймпадом; открыть virtual keyboard; сменить язык; переименовать длинную запись.

**Expected result:** нет горизонтального overflow/обрезанных управляющих кнопок; фокус и прокрутка доступны контроллером; RU/EN меняются без перезапуска; длинные ошибки прокручиваются.

**Failure data to collect:** фото/видео экрана, разрешение, язык, точная последовательность фокуса.

### Блокирующий сценарий импорта WG/AWG

**Prerequisites:** один рабочий WireGuard `.conf` и один рабочий AmneziaWG `.conf` в `/home/deck/Downloads` или вложенной папке.

**Steps:** Add VPN → WireGuard или AmneziaWG → перейти к файлу → нажать на строку файла → проверить имя → Import.

**Expected result:** профиль сразу появляется в главном списке. Ошибка выбора/доступа/parser/storage остаётся на экране и в toast вместе со стабильным code, например `CONFIG_FILE_NOT_ACCESSIBLE`; «ничего не произошло» недопустимо.

**Failure data to collect:** `path`/`realpath`, protocol, error code и `DECKY_PLUGIN_LOG_DIR/vdeck.log`. Не прикладывать config, PrivateKey, PresharedKey или passwords.

### Повторная приёмка frontend Import — 2026-09-02

1. Установить новый локальный `V-Deck-v0.1.0.zip` и перезапустить плагин через Decky.
2. Add VPN → AmneziaWG → выбрать `/home/deck/Downloads/AWGSD.vpn`.
3. Убедиться, что отображается форма с путём и именем `AWGSD`; Import активна. Пустое имя намеренно отключает кнопку и сопровождается подсказкой.
4. Нажать именно кнопку Import в форме V-Deck (отдельно от выбора файла в file picker).
5. Ожидание: профиль появляется в главном списке, форма закрывается. Повторить с WireGuard `.conf`.
6. Повторить, закрыв и открыв Quick Access Menu между выбором файла и нажатием Import. Форма и имя должны сохраниться.
7. Отдельно проверить нажатие контроллером и touch/мышью: локальные DOM-тесты не эмулируют Steam focus router.

В «Журнале импорта» / «Import debug log» в UI и в `DECKY_PLUGIN_LOG_DIR/vdeck.log` ожидаются frontend-события:

```text
import form rendered (busy=false, filePathPresent=true, namePresent=true)
import button pressed
importSelected entered (protocol=amneziawg, rpcStarted=false)
RPC import_connection starting
RPC import_connection returned success
refresh after import started
fresh snapshot contains 1 connections
import completed
```

Backend дополнительно пишет `import_connection started`, `parser succeeded`, `storage stage created`, `connection committed` и `snapshot contains 1 connections` для первого профиля. Если уже есть профили, ожидается соответствующее общее число. Frontend-события передаются неблокирующе; `sequence` задаёт порядок внутри frontend-журнала. При недоступном logging RPC последние 80 frontend-событий остаются в памяти UI и browser console, даже если в `vdeck.log` их нет.

Если `import form rendered` есть, а `import button pressed` отсутствует, обработчик кнопки не был вызван: сохранить снимок формы, способ нажатия, версию SteamOS/Decky и журнал. Если `import failed` содержит `rpcStarted=false`, ошибка возникла до импортирующего RPC; UI покажет `IMPORT_FRONTEND_FAILED`. При отказе транспорта — `IMPORT_RPC_FAILED`, при сбое обновления — `IMPORT_REFRESH_FAILED`, при отсутствии созданного ID в snapshot — `IMPORT_NOT_VISIBLE`.

Доказанный локальный дефект: официальный Decky `PluginView` удаляет `content`, когда QAM скрыт и `alwaysRender` не включён. Promise file picker продолжает работу, `validate_import` завершается, но `setFilePath/setValidation/setPage` относятся к уже размонтированному компоненту. При возврате появляется новая пустая форма состояния/main. Регрессионный тест воспроизводил это до исправления и проходит с `alwaysRender: true`. Это объяснение сценария потери формы, **не доказательство причины нажатия на видимую активную кнопку на конкретном устройстве**. Физическая приёмка пока не проведена.

Официальные исходники проверены 2026-09-02 (GitHub использовался только на чтение):

- [Decky PluginView, commit b4b8be3](https://github.com/SteamDeckHomebrew/decky-loader/blob/b4b8be3297e427dad6fbc6697ffdb765a796f7fd/frontend/src/components/PluginView.tsx) — условие `(visible || activePlugin.alwaysRender) && activePlugin.content`.
- [ButtonItem, commit 247eb63](https://github.com/SteamDeckHomebrew/decky-frontend-lib/blob/247eb635ea7acdc3e7807d5f99722daf854aaa70/src/components/ButtonItem.ts) — `onClick(e: MouseEvent): void`; текущая синхронная обёртка `() => void importSelected()` корректна. Реализация контрола берётся из Steam webpack, а не написана в библиотеке Decky.
- [API callable/openFilePicker, commit d1b7f16](https://github.com/SteamDeckHomebrew/loader-api/blob/d1b7f16070777a0ada939cbacd3606eeba0574f5/src/index.ts) и [Loader implementation](https://github.com/SteamDeckHomebrew/decky-loader/blob/b4b8be3297e427dad6fbc6697ffdb765a796f7fd/frontend/src/plugin-loader.tsx) — positional arguments; picker возвращает `path`/`realpath`. Шесть аргументов `import_connection` соответствуют Python-методу.

Parser, permissions, storage и VPN runtime в этом follow-up не менялись. React DOM/jsdom используются только для локальных тестов; release продолжает использовать React и UI из Steam/Decky.

### Текущий BLOCKER: запуск userspace AWG/WG (2026-09-02)

Пользователь подтвердил, что импорт на физическом Steam Deck теперь проходит полностью. Следующая приёмка относится к подключению; её успешность пока не подтверждена.

До исправления запуск был `<plugin>/bin/amneziawg-go vdeck-<uuid8>` (аналогично `wireguard-go`) с унаследованным environment и только `WG_TUN_NAME_FILE=""`. Оба upstream daemon без foreground создают child и завершают parent; V-Deck ошибочно считал завершение parent через 50 мс неуспешным запуском. Плашка `kernel has first class support` — не проверка kernel module. Реальные старые PID/exit code/TUN/UAPI в предоставленных логах отсутствуют; код 0 нельзя выдавать за измеренный на устройстве.

Новый общий userspace command:

```text
<plugin>/bin/amneziawg-go --foreground vdeck-<uuid8>
# или, только для WireGuard fallback:
<plugin>/bin/wireguard-go --foreground vdeck-<uuid8>
```

Явные environment overrides: `WG_PROCESS_FOREGROUND=1`, `LOG_LEVEL=error`, `WG_TUN_FD=""`, `WG_UAPI_FD=""`, `WG_TUN_NAME_FILE=""`. Остальное окружение наследуется, но целиком в log не выводится. Пустые FD предотвращают использование чужих унаследованных дескрипторов; `LOG_LEVEL=error` не включает verbose-дампы. `WG_PROCESS_FOREGROUND=1` также подавляет вводящую в заблуждение Linux-плашку, которая печатается до разбора CLI-флага.

**Steps:** установить новый ZIP, перезапустить плагин; выбрать уже импортированный AWG профиль; Connect; проверить handshake/трафик; Disconnect; повторить Connect/Disconnect. Отдельно в контролируемом тесте проверить crash/recovery только PID своего VPN процесса, сверив executable и start time с runtime. Не использовать `pkill`/`killall` по имени бинарника. WireGuard: проверить kernel-first и отдельно userspace fallback в подходящей среде, не удаляя модули ядра на пользовательском Deck.

**Expected log:** `starting userspace backend ... foreground=true` → `userspace process owned ... pid=...` → `startup process alive` → `UAPI ready` → `VPN setconf succeeded`. Далее требуется подтверждение handshake; один живой процесс не означает успешного VPN. UAPI: `/var/run/amneziawg/<interface>.sock` для AWG, `/var/run/wireguard/<interface>.sock` для WG fallback.

При отказе: `process exited` / `userspace startup failed`, с `pid`, `exit_code`, `interface_exists`, `uapi_exists`, `code`. `exit_code=None/unknown` означает отсутствие измеренного exit status (например, живой процесс при timeout или PID после перезапуска Loader), а не код 0. Состояние процессов контролируется по сохранённому PID/start ticks/executable; проверка readiness включает TUN, подключение к Unix socket и успешный setconf до address/routes/DNS. Существовавшие до попытки интерфейс/socket не заменяются. Cleanup удаляет оставшийся socket только при совпадении записанного inode/device.

**Failure data:** версия SteamOS/Decky, `vdeck.log`, отдельный `<connection UUID>.log`, PID/exit code и наличие интерфейса/socket. Никаких config, PrivateKey, PresharedKey и паролей. Если возникает `INTERFACE_ALREADY_EXISTS`, не удалять найденные ресурсы вручную без проверки владельца; возможен остаток старого daemonized запуска.

Локальные lifecycle-тесты используют настоящий backend/manager/storage с имитацией Linux OS-границы; process tests запускают и останавливают реальные локальные Python child-процессы. Это не заменяет запуск bundled Linux ELF на Steam Deck.

Источники: [AWG pinned main.go](https://github.com/amnezia-vpn/amneziawg-go/blob/b5928efb6ca19f0153958460c3d141f04abc5c2e/main.go), [WG pinned main.go](https://github.com/WireGuard/wireguard-go/blob/f333402bd9cbe0f3eeb02507bd14e23d7d639280/main.go). Текущие official master также проверены; foreground/daemonization поведение совпадает.

## 3. Миграция из vpn-deck

**Prerequisites:** рабочая старая конфигурация в `~/.local/share/vpn-deck/configs`; backup каталога.

**Steps:** запустить V-Deck впервые; проверить найденную/импортированную запись; запустить V-Deck второй раз; открыть старый vpn-deck.

**Expected result:** V-Deck создаёт собственную копию один раз; исходник/старый plugin не меняются; повторный запуск не создаёт дубликат; ошибка отдельного файла не отменяет остальные импорты.

**Failure data to collect:** список файлов до/после с timestamps и permissions, migration state, санитизированный report.

## 4. AmneziaWG legacy, 2.x и 3.1 `.conf`

**Prerequisites:** три реальные рабочие конфигурации от соответствующих серверов; AWG 3.1 профиль с новыми `I*`, `S*`, `H*` и timing/padding fields.

**Steps:** отдельно импортировать каждую как AmneziaWG; подключить; открыть diagnostics; передать трафик; выключить.

**Expected result:** handshake подтверждён; RX/TX растут; public IP меняется; ping/session отображаются; 3.1 fields не удалены из внутренней runtime config; OFF полностью очищает интерфейс/маршруты/DNS.

**Failure data to collect:** protocol/server versions, санитизированная config field list, `awg show`, V-Deck report.

## 5. Native Amnezia `.vpn`

**Prerequisites:** свежий экспорт актуального Amnezia client с одним AWG/AWG2 контейнером.

**Steps:** Add VPN → AmneziaWG → выбрать `.vpn`; подключить; проверить трафик и diagnostics.

**Expected result:** файл декодируется как Qt qCompress/Base64URL JSON, выбирается AWG container, исходный файл не меняется, соединение работает. Неизвестный формат получает стабильную ошибку, не частичный импорт.

**Failure data to collect:** версия Amnezia client, только структура/имена JSON-полей без секретов, error code.

## 6. WireGuard full tunnel и userspace fallback

**Prerequisites:** рабочий стандартный `.conf`; возможность временно проверить систему с kernel WireGuard и без него.

**Steps:** импортировать как WireGuard; подключить с доступным kernel module; повторить в среде, где `ip link add ... type wireguard` завершается ошибкой.

**Expected result:** сначала используется kernel interface; при невозможности запускается bundled `wireguard-go`; handshake, route, DNS, RX/TX и OFF работают одинаково.

**Failure data to collect:** `uname -a`, `ip -details link`, `wg show`, backend log/report.

## 7. OpenVPN inline

**Prerequisites:** рабочий `.ovpn` с inline `<ca>`, `<cert>`, `<key>` и при необходимости `<tls-crypt>`.

**Steps:** импортировать; подключить; передать трафик; открыть diagnostics; выключить.

**Expected result:** management state сообщает CONNECTED (не случайная log-строка), RX/TX доступны, config не пишет в произвольные пути, OFF останавливает процесс и удаляет TUN/DNS.

**Failure data to collect:** OpenVPN server version/cipher, management state, санитизированный log/report.

## 8. OpenVPN external files

**Prerequisites:** `.ovpn` с относительными `ca`, `cert`, `key`, `tls-auth`/`tls-crypt` файлами.

**Steps:** импортировать; переместить или удалить исходную папку Downloads; подключить.

**Expected result:** зависимости скопированы внутрь V-Deck и connection продолжает работать. Отсутствующий файл, absolute path, `../` и symlink escape блокируются до сохранения записи.

**Failure data to collect:** имена директив/файлов без содержимого, permissions внутренней копии, error code.

## 9. OpenVPN username/password

**Prerequisites:** профиль с `auth-user-pass`, один правильный и один неправильный credential set.

**Steps:** импортировать; ввести неправильные данные; подключить; затем сохранить правильные и повторить.

**Expected result:** данные вводятся virtual keyboard, не видны повторно, не попадают в process args/metadata/log; неправильные данные дают понятную auth error без бесконечного retry; правильные подключают.

**Failure data to collect:** error code, `ps` args с замазанными путями, permissions credential file; пароль не собирать.

## 10. OpenVPN encrypted private key

**Prerequisites:** профиль с encrypted private key и passphrase.

**Steps:** импортировать; ввести неверную passphrase; затем правильную; переподключить после рестарта Decky.

**Expected result:** UI спрашивает passphrase, сохраняет в отдельном `0600` файле, не отображает сохранённое значение; неверное значение завершается ошибкой; правильное работает после рестарта.

**Failure data to collect:** тип ключа без содержимого, error code, file mode.

## 11. Переключение AWG → WG → OpenVPN → AWG

**Prerequisites:** три рабочих профиля.

**Steps:** включить AWG; затем WG без ручного OFF; затем OpenVPN; затем AWG.

**Expected result:** всегда существует максимум один managed process/interface; A полностью остановлен до запуска B; UI не зависает при быстрых повторных нажатиях.

**Failure data to collect:** временная шкала state, `ip link`, process list, routes, report.

## 12. Ошибка переключения

**Prerequisites:** рабочий A; B с недоступным endpoint.

**Steps:** включить A; включить B; дождаться timeout.

**Expected result:** A остановлен, B в ERROR/OFF, A автоматически не восстановлен, обычный интернет доступен, нет half-active process/interface/firewall.

**Failure data to collect:** state/error history, interfaces/routes/nft/process list.

## 13. Kill switch: нормальная работа и initial failure

**Prerequisites:** рабочий full-tunnel профиль; нерабочий профиль; подтверждённое предупреждение Kill Switch.

**Steps:** включить рабочий VPN и Kill Switch; проверить IPv4/IPv6; OFF; затем попытаться впервые включить нерабочий VPN.

**Expected result:** при connected трафик идёт через VPN; `inet vdeck` не затрагивает чужие таблицы; manual OFF восстанавливает интернет. При initial failure kill switch не остаётся и обычный интернет работает.

**Failure data to collect:** `sudo nft list ruleset`, route/interface list, external IP tests.

## 14. Kill switch: потеря туннеля и исчерпание recovery

**Prerequisites:** connected VPN с Kill Switch ON; возможность остановить server/process.

**Steps:** оборвать туннель; проверить direct traffic во время recovery; оставить endpoint недоступным до исчерпания попыток; затем нажать manual OFF.

**Expected result:** direct IPv4/IPv6 заблокирован после потери ранее установленного туннеля; state RECOVERING → ERROR; firewall остаётся; manual OFF удаляет только `inet vdeck` и восстанавливает интернет.

**Failure data to collect:** recovery timestamps, nft rules, ping/curl results, report.

### Hostname endpoint и смена IP

**Prerequisites:** профиль с hostname endpoint, Kill Switch ON, возможность изменить DNS A/AAAA запись тестового VPN-сервера.

**Steps:** подключиться; остановить старый endpoint; изменить A/AAAA; дождаться recovery; во время восстановления проверить обычный direct IPv4/IPv6 traffic и `sudo nft list table inet vdeck`.

**Expected result:** первая попытка использует кешированный IP; затем DNS разрешается только через временные правила к конкретным системным DNS-серверам; новый endpoint подключается; обычный direct traffic всё время заблокирован; временные DNS rules после resolve отсутствуют.

## 15. Wi‑Fi, hotspot и Ethernet transitions

**Prerequisites:** connected VPN; Wi‑Fi A/B, телефонный hotspot, при наличии Ethernet.

**Steps:** Wi‑Fi off/on; A → B; Wi‑Fi → hotspot; Wi‑Fi ↔ Ethernet.

**Expected result:** NetworkManager event запускает bounded recovery; не возникает polling раз в секунду; desired ON восстанавливается; одновременно один tunnel.

**Failure data to collect:** `nmcli monitor` timeline, V-Deck state/error history, route/DNS state.

## 16. Sleep/resume и manual OFF

**Prerequisites:** connected VPN, затем отдельный прогон с VPN вручную OFF.

**Steps:** sleep на 2–10 минут; resume; повторить после manual OFF и network change.

**Expected result:** при desired ON tunnel проверяется/восстанавливается; после manual OFF resume/network event не включает VPN сам.

**Failure data to collect:** timestamps до/после resume, state.json без секретов, logs.

## 17. Auto-connect semantics

**Prerequisites:** Auto-connect setting; рабочий профиль.

**Steps:** (a) Auto-connect OFF + VPN active → reboot; (b) Auto-connect OFF + VPN active → перезапустить только V-Deck/Decky в той же загрузочной сессии; (c) Auto-connect ON + VPN active → reboot; (d) Auto-connect ON + пользователь нажал OFF → reboot/restart Decky.

**Expected result:** (a) после cold boot не включается; (b) same-boot restart восстанавливает last active, потому что `desired_state=ON`, независимо от Auto-connect; (c) cold boot восстанавливает last active; (d) остаётся выключенным. Cold boot и restart различаются по Linux boot ID, а manual OFF — по `desired_state`.

**Failure data to collect:** sanitized persistent/runtime state и startup log.

## 18. IPv6 leak warning/protection

**Prerequisites:** underlay с public IPv6; VPN без IPv6 routes.

**Steps:** подключить без Kill Switch и открыть diagnostics; повторить с Kill Switch; выполнить независимый IPv6 request.

**Expected result:** без Kill Switch warning о possible leak; с Kill Switch direct IPv6 заблокирован и diagnostics сообщает protection; IPv4 tunnel не ломается.

**Failure data to collect:** `ip -6 addr/route`, nft table, результаты независимого IPv6 endpoint.

## 19. Diagnostics, ping cache и интервал

**Prerequisites:** active profile; наблюдение трафика не менее 3 минут.

**Steps:** refresh diagnostics; проверить tunnel/handshake, RX/TX, routing, IPv4/IPv6, external IP, ping, session; закрыть UI; наблюдать probes; OFF.

**Expected result:** partial external-IP failure не скрывает остальные checks; split tunnel routing = NOT_APPLICABLE; ping выполняется не чаще примерно 60 s для active connection; last ping остаётся на card после OFF; report маскирует public IP и секреты.

**Failure data to collect:** timestamps ICMP/HTTP probes, JSON report после ручного secret review.

## 20. Удаление активной записи

**Prerequisites:** active VPN.

**Steps:** удалить active connection с подтверждением.

**Expected result:** сначала stop и internet restore, затем запись/config/credentials удалены; нет процесса, интерфейса, routes, DNS или firewall leftovers.

**Failure data to collect:** filesystem tombstone/state, network/process lists.

## 21. Controlled crash и startup cleanup

**Prerequisites:** connected VPN; backup; доступ к Desktop Mode/SSH.

**Steps:** контролируемо завершить backend/plugin process; перезапустить Decky; повторить с повреждённой/удалённой metadata записью.

**Expected result:** startup удаляет только V-Deck resources, проверяет PID identity, не завершает unrelated reused PID, затем auto-connect следует desired state. Чужие routes/firewall остаются.

**Failure data to collect:** before/after process start ticks, interfaces, proto-186 routes, nft tables, errors.

## 22. Malicious import regression

**Prerequisites:** синтетические profiles с OpenVPN hooks/plugins/management/log/status/writepid/absolute/traversal/symlink paths и WG PreUp/PostUp.

**Steps:** импортировать каждый файл; проверить storage и system audit logs.

**Expected result:** импорт отклонён стабильным `CONFIG_UNSAFE_DIRECTIVE`/path error до создания connection; ни одна команда не выполнена, произвольный файл не прочитан/создан.

**Failure data to collect:** synthetic file, exact error code, filesystem audit. Не использовать реальные secrets.

## 23. Diagnostic export secret review

**Prerequisites:** профили каждого протокола с заведомыми синтетическими marker secrets.

**Steps:** создать errors/log lines с markers; экспортировать report; искать private-key/password/token/cert blocks, management password, endpoint и полный public IP.

**Expected result:** секреты/inline blocks отсутствуют или `[REDACTED]`; public IP маскирован; endpoint не экспортирован; размер report bounded.

**Failure data to collect:** только redacted diff и sanitizer test marker, никогда реальный секрет.

## 24. Uninstall cleanup and rollback proof

**Prerequisites:** завершены все сценарии; снимок чужих firewall/routes до теста.

**Steps:** manual OFF; удалить plugin; reboot; сравнить сеть; при необходимости установить предыдущий release.

**Expected result:** обычный интернет/DNS работают; чужая конфигурация неизменна; плагин можно переустановить/откатить без ручной починки SteamOS.

**Failure data to collect:** diff ownership-scoped network state, Decky uninstall log.
