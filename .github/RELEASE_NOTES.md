# V-Deck 0.1.0 — public preview / публичная тестовая версия

## Русский

Обновление Decky Loader VPN-плагина для Steam Deck: AmneziaWG, WireGuard и OpenVPN из Gaming Mode. Релизный тег `v0.1.0-preview.2`, версия плагина остаётся `0.1.0`. Это тестовый релиз, не обещание полной совместимости или отсутствия утечек.

### Что изменилось

- Исправлен полный импорт через Decky File Picker, сохранение формы и показ ошибок; добавлены безопасные логи этапов.
- Исправлены foreground/lifecycle AWG и WG userspace, PyInstaller-окружение системных команд, нормализация нативных `.vpn`, DNS, owned routes и cleanup при сбоях.
- Исправлены автоподключение до появления сети и восстановление Wi-Fi с Kill Switch; ручное OFF отменяет восстановление.
- Исправлена раскладка кнопок, добавлена ручная проверка внешнего IPv4 до/после VPN (ipify + icanhazip, HTTPS, без передачи конфигурации). Последний фикс загрузки системных CA ещё ждёт проверки на Deck.
- Добавлены инструкции на русском/английском, матрица подтверждённых результатов и ограничений.

### Что проверено

Пользователь подтвердил на физическом Steam Deck: AWG `.conf`/`.vpn`, подключение и доступ к игровому серверу, пинг, RU/EN, кнопки, перезагрузку и Wi-Fi OFF/ON с KS + автоподключением. WireGuard/OpenVPN проверены только локально с mocked сетью. Локально проходят 215 backend + 31 frontend тест и статический/build/release suite. Это не физическая гарантия работы всех функций.

OpenVPN требует локальные маршруты/redirect-gateway и DNS; server-push-only пока не поддержан. Не подтверждены новый IP/TLS фикс на Deck, suspend/resume, все IPv6/DNS-утечки и совместная работа с другими VPN.

### Установка и документы

Скачайте **V-Deck-v0.1.0.zip** ниже → Decky Settings → Developer → установка из ZIP. При обновлении сначала выключите VPN и сохраните исходные профили. Docker и отдельные VPN-пакеты на Steam Deck не нужны.

- [Инструкция пользователя](https://github.com/GoldDGaro/V-Deck/blob/v0.1.0-preview.2/USER_GUIDE_RU.md)
- [Матрица проверок](https://github.com/GoldDGaro/V-Deck/blob/v0.1.0-preview.2/VALIDATION.md)
- [Все изменения](https://github.com/GoldDGaro/V-Deck/blob/v0.1.0-preview.2/CHANGELOG.md)

`V-Deck-v0.1.0-source.zip` — соответствующие исходники проекта и bundled компонентов, не установщик. Автоматические GitHub `Source code` также не являются установщиком. Сверяйте файлы с `SHA256SUMS.txt` этого релиза.

Лицензия оригинального кода: **PolyForm Noncommercial 1.0.0** (source-available, не MIT и не OSI open source). Публичность не меняет некоммерческие условия; bundled компоненты сохраняют собственные лицензии. Не публикуйте профили, ключи, пароли или необработанные логи в Issues.

## English

Updated Decky Loader VPN manager for Steam Deck Gaming Mode: AmneziaWG, WireGuard and OpenVPN. Release tag `v0.1.0-preview.2`, plugin version `0.1.0`. This is a preview, not a compatibility or leak-free guarantee.

### Changes

- Fix Decky file-picker/import state retention, visible errors and safe stage logs.
- Fix AWG/WG userspace foreground lifecycle, host subprocess PyInstaller environment, native `.vpn` normalization, DNS, owned routes and failure cleanup.
- Fix early-boot auto-connect and Wi-Fi recovery with KS; manual OFF cancels recovery.
- Correct button layout; add manual before/after external IPv4 checks using verified HTTPS (ipify + icanhazip, no configuration upload). The latest host-CA fix still needs physical validation.
- Add RU/EN user guides and explicit validation/limitation documentation.

### Evidence and limitations

Physical user feedback confirms AWG `.conf`/`.vpn`, connection and game-server traffic, ping, RU/EN, buttons, reboot and Wi-Fi OFF/ON with KS + auto-connect. WireGuard/OpenVPN have local mocked coverage only. Local checks pass 215 backend + 31 frontend tests and the static/build/release suite; they do not prove every physical scenario.

OpenVPN requires local routes/redirect-gateway and DNS; server-push-only profiles are unsupported. The latest IP/TLS fix on Deck, suspend/resume, comprehensive IPv6/DNS leak testing and concurrent VPN compatibility remain unverified.

### Installation

Install **V-Deck-v0.1.0.zip** below through Decky Settings → Developer → ZIP installation. Disconnect and back up original profiles before updating. No Docker or separately installed VPN packages are needed on Steam Deck.

- [English user guide](https://github.com/GoldDGaro/V-Deck/blob/v0.1.0-preview.2/USER_GUIDE_EN.md)
- [Validation matrix](https://github.com/GoldDGaro/V-Deck/blob/v0.1.0-preview.2/VALIDATION.md)
- [Changelog](https://github.com/GoldDGaro/V-Deck/blob/v0.1.0-preview.2/CHANGELOG.md)

The `-source.zip` contains corresponding project/third-party source, not an installer. GitHub's automatic `Source code` archives are not installers either. Verify downloads using this release's `SHA256SUMS.txt`.

Original code remains **PolyForm Noncommercial 1.0.0**, source-available rather than OSI-approved open source. Third-party licenses remain separate. Never publish profiles, keys, passwords or raw logs in Issues.
