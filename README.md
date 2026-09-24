# V-Deck 0.2.0

**VPN на Steam Deck из Gaming Mode.** [English](#english)

V-Deck — плагин [Decky Loader](https://decky.xyz/) для управления VPN-подключениями.
Нужен собственный сервер или действующая подписка VPN-провайдера.
V-Deck не предоставляет VPN-сервис и не является официальным приложением Amnezia.

> [!IMPORTANT]
> Предварительная версия. Совместимость зависит от конфигурации и сети.
> Полная поддержка всех протоколов, длительная стабильность и отсутствие
> DNS/IPv6-утечек не гарантируются. Проверка на устройствах продолжается.

**[Скачать v0.2.0](https://github.com/GoldDGaro/V-Deck/releases/tag/v0.2.0)** ·
[Установка](#установка) · [English](#english) · [Changelog](CHANGELOG.md)

## Возможности

| Подключение | Поддерживаемый импорт |
| --- | --- |
| AmneziaWG | `.conf`, поддерживаемые нативные Amnezia `.vpn` |
| Amnezia Premium | Ключ подписки `.vpn`, выбор доступной страны |
| WireGuard | `.conf`; kernel и userspace fallback |
| OpenVPN | `.ovpn`; необходимы локально заданные маршруты и DNS |
| Xray Reality — экспериментально | Клиентский JSON или одна ссылка `vless://` в файле; VLESS TCP/RAW |

- Одно активное подключение, переименование и удаление профилей.
- Автоподключение и восстановление после обрыва.
- Опциональный Kill Switch; ручное отключение разрешает обычный интернет.
- Диагностика состояния, пинг через VPN, ручная проверка внешнего IPv4.
- Русский и английский интерфейс.
- Дневные логи: текущий и два предыдущих дня.

Предварительный замер задержки Premium-локаций до добавления не поддерживается.
Для смены страны сначала отключите профиль. Не все форматы Xray поддерживаются;
OpenVPN с маршрутами и DNS только от server push не поддерживается.

## Установка

1. Установите Decky Loader на Steam Deck.
2. Скачайте **V-Deck-v0.2.0.zip** из релиза. Source ZIP — не установщик.
3. Перед обновлением отключите VPN и сохраните исходные конфигурации.
4. В Decky откройте Settings → Developer → установку плагина из ZIP.
5. Откройте V-Deck → «Добавить VPN», выберите тип и файл, затем завершите импорт.

Docker и отдельная установка VPN-клиентов на Steam Deck не нужны: бинарники входят
в ZIP, Python предоставляет Decky. Плагину необходимы повышенные права для управления сетью.

## Диагностика и приватность

Пинг через VPN не равен задержке конкретного приложения. Изменение внешнего IPv4
не доказывает отсутствие DNS/IPv6-утечек. При ошибке отключите VPN и запишите код.

Телеметрии нет. Проверка внешнего IPv4 по кнопке обращается к ipify/icanhazip по HTTPS.
Сетевые проверки используют контрольные адреса. Premium обращается к сервису
провайдера с данными подписки для выбранной операции.
Не публикуйте ключи, конфигурации, подписки или необработанные логи.
Технические журналы могут содержать пути и сетевые адреса.

## Лицензия и безопасность

- [Безопасность](SECURITY.md)
- [Лицензии компонентов](THIRD_PARTY_NOTICES.md), [соответствующие исходники](SOURCE_OFFER.md)

Оригинальный код: **PolyForm Noncommercial 1.0.0** — source-available,
не OSI open source. Сторонние компоненты сохраняют собственные лицензии.
Docker используется только при сборке/CI.

## English

**V-Deck** manages VPN connections in Steam Deck Gaming Mode through Decky Loader.
Bring your own server configuration or valid provider subscription. V-Deck is not
a VPN service or an official Amnezia application.

**[Download v0.2.0](https://github.com/GoldDGaro/V-Deck/releases/tag/v0.2.0)** ·
[Changelog](CHANGELOG.md)

Supports AmneziaWG conf/native vpn, Amnezia Premium subscription import and country
selection, WireGuard conf, OpenVPN ovpn and experimental Xray VLESS Reality TCP/RAW
client JSON or a single vless URI in a file. Includes auto-connect, recovery,
optional Kill Switch, diagnostics, manual external IPv4 checks and RU/EN UI.
Only one VPN is active. Disconnect before changing a Premium country.
Pre-add Premium location latency measurement is not supported.

Install **V-Deck-v0.2.0.zip** through Decky's Developer ZIP installer. Disconnect
and keep your original profiles before updating. Source ZIPs are not installers.
VPN clients are bundled; Docker is build-only and is not needed on Steam Deck.

This is a preview. Full protocol compatibility, long-session stability and complete
DNS/IPv6 leak protection are not guaranteed. OpenVPN server-push-only routing/DNS
and unsupported Xray transports are outside the current scope.

No telemetry. Explicit IPv4 checks contact ipify/icanhazip over HTTPS; connection
checks use control destinations. Premium credentials are sent to the provider for
requested operations. Never publish subscriptions, keys, profiles or raw logs.

Original code: **PolyForm Noncommercial 1.0.0**, source-available, not OSI open source.
Bundled components retain their licenses; corresponding source accompanies the release.
