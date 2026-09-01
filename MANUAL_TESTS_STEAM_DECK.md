# V-Deck 0.1.0 — ручная приёмка на Steam Deck

Автоматические проверки не заменяют тесты на физическом Steam Deck. Используйте синтетические имена/адреса в отчётах и никогда не прикладывайте реальные ключи или пароли. Для каждого сбоя сохраните версию SteamOS, Decky, модель Deck, протокол, код ошибки V-Deck и санитизированный diagnostic report.

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

**Steps:** (a) Auto-connect OFF → reboot; (b) ON + VPN active → reboot/restart Decky; (c) ON + пользователь нажал OFF → reboot.

**Expected result:** (a) не включается; (b) восстанавливает last active; (c) остаётся выключенным. Критерий определяется `desired_state`, не одним флагом auto-connect.

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
