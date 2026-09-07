# Validation status / Статус проверки

Applies to plugin **0.1.0**, release **v0.1.0-preview.2**, prepared 2026-09-07.

## Русский

Публичная предварительная версия. Физические результаты ниже получены от пользователя на его Steam Deck, а не из собственной лаборатории и не на всех комбинациях SteamOS/Decky/серверов. Точные версии ОС/Decky в этих результатах не зафиксированы. Успешный mocked test проверяет логику, но не заменяет сетевой тест на устройстве.

| Сценарий | Подтверждение | Граница утверждения |
| --- | --- | --- |
| AWG `.conf` и нативный `.vpn`: импорт, запуск, подключение | Пользователь на Steam Deck; runtime-логи | Работало в проверенной конфигурации, не любой экспорт AWG |
| Доступ к игровому серверу через AWG, отключение/повторное подключение | Отчёт пользователя | Не бенчмарк, не проверка всех маршрутов/утечек |
| Пинг, сохранённый пинг неактивного профиля, RU/EN, кнопки | Отчёт пользователя | Не все разрешения/варианты Steam UI |
| Перезагрузка и Wi-Fi OFF/ON с KS + автоподключением | Последующий отчёт пользователя после исправлений | Не roaming между сетями, не сон/пробуждение, не исчерпывающий тест KS |
| Внешний IPv4 до/после VPN | Локальные transport/UI-тесты и реальные HTTPS-запросы на Windows с явным CA | На Deck ранее был `SSLCertVerificationError`; последний host-CA фикс ещё физически не подтверждён |
| WireGuard kernel/userspace Connect → Disconnect | Mocked end-to-end | Физического теста пока нет |
| OpenVPN Connect → Disconnect, management, credentials | Mocked тесты | Физического теста нет; server-push-only routes/DNS не поддержаны |
| Cleanup, ошибки, manual OFF, переключение, recovery/KS | Локальные regression/integration tests | Не все реальные гонки, остановки питания и системные сетевые стеки |

Локально: **215 backend + 31 frontend тест**, Ruff format/check, mypy (в том числе Linux platform mode), frozen pnpm install, Prettier, ESLint, TypeScript, Rollup и `git diff --check`. Релиз проходит `build_release`, `verify_release`, `verify_source`, проверку ELF/хешей/прав и сверку распакованных файлов с текущими исходниками. Итоговые результаты CI доступны в [GitHub Actions](https://github.com/GoldDGaro/V-Deck/actions); зелёный CI не подтверждает физическую VPN-работоспособность.

Native binaries не менялись в обновлении: пять закреплённых Linux x86-64 ELF проходят проверку отсутствия `PT_INTERP`/`DT_NEEDED`, хеши в [manifest](backend/versions.json). Локальный Windows-прогон не выдаётся за запуск Linux binaries или новый Docker build. Docker нужен только при пересборке native компонентов, не в runtime.

Ещё нужны физические тесты: WG kernel/fallback, OpenVPN с совместимым сервером, новый IP/TLS путь, suspend/resume, разные Wi-Fi/DNS/IPv6-сети, независимые проверки DNS/IPv6-утечек и длительная стабильность. Сообщение о конфликте с VPN Deck пока не локализовано: совместимость с параллельными VPN не обещается. OpenVPN push-only, WG custom Table и вставка `vpn://` — **неподдерживаемые функции**, а не просто непроверенные.

Полная ручная матрица: [MANUAL_TESTS_STEAM_DECK.md](MANUAL_TESTS_STEAM_DECK.md). При отправке результатов не прикладывайте реальные профили/секреты или необработанные логи публично.

## English

This is a public preview. Physical evidence comes from the user's Steam Deck, not an independent lab or every SteamOS/Decky/server combination. Exact OS/Decky versions were not recorded in that feedback. Mocked tests validate logic, not physical networking.

| Scenario | Evidence | Limit |
| --- | --- | --- |
| AWG `.conf`/native `.vpn` import and connection | User's physical test and runtime logs | Tested configuration, not every AWG export |
| Game-server access over AWG, disconnect/reconnect | User feedback | Not a benchmark or comprehensive route/leak test |
| Active/cached ping, RU/EN, corrected buttons | User feedback | Not every Steam UI variant/resolution |
| Reboot and Wi-Fi OFF/ON with KS + auto-connect | Subsequent user feedback after fixes | Not roaming, suspend/resume or exhaustive KS validation |
| External IPv4 before/after | Local transport/UI tests and real HTTPS on Windows with explicit CA | Earlier Deck logs show certificate rejection; latest host-CA fix still awaits physical validation |
| WG kernel/userspace lifecycle | Mocked end-to-end | No physical test yet |
| OpenVPN lifecycle, management, credentials | Mocked tests | No physical test; server-push-only routes/DNS unsupported |
| Cleanup, failures, manual OFF, switching, recovery/KS | Regression/integration tests | Not every real race, power loss or network stack |

Local checks: **215 backend + 31 frontend tests**, Ruff format/check, mypy (including Linux platform mode), frozen pnpm install, Prettier, ESLint, TypeScript, Rollup and `git diff --check`. Release/source verification checks archive contents, native ELF/hashes/modes and extracted files against the source tree. See [GitHub Actions](https://github.com/GoldDGaro/V-Deck/actions) for CI outcomes; green CI is not physical VPN acceptance.

The five pinned Linux x86-64 native binaries are unchanged, with no `PT_INTERP`/`DT_NEEDED` per ELF audit and hashes in [the manifest](backend/versions.json). The local Windows run is not Linux binary execution or a fresh Docker rebuild. Docker is build-only.

Still physical-only: WG kernel/fallback, compatible OpenVPN servers, the new IP/TLS path, suspend/resume, multiple Wi-Fi/DNS/IPv6 environments, independent IPv6/DNS leak testing and long-term stability. A reported VPN Deck conflict remains unlocalized; concurrent VPN compatibility is not promised. OpenVPN push-only, WG custom Table and `vpn://` paste are **unsupported**, not merely untested. Follow the [manual matrix](MANUAL_TESTS_STEAM_DECK.md) and never post secrets/raw logs publicly.
