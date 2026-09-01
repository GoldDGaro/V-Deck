# Changelog

## 0.1.0 — 2026-08-31

- Initial V-Deck release.
- Added real AmneziaWG 3.1, WireGuard, and OpenVPN backends.
- Added `.conf`, native Amnezia `.vpn`, and `.ovpn` import with strict safety validation.
- Added single-active orchestration, recovery, desired-state auto-connect, crash cleanup, per-link DNS, route ownership, and optional IPv4/IPv6 kill switch.
- Added Gaming Mode UI, Russian and English localization, credentials UI, diagnostics, report export, migration, tests, CI, reproducible native builds, binary-integrity checks, and verified release packaging.
- Improved AmneziaWG/WireGuard health checks with an interface-bound active probe plus route, handshake, RX, and TX confirmation.
- Added endpoint IP caching and narrowly scoped temporary DNS recovery rules so hostname endpoints recover under Kill Switch without opening ordinary traffic.
- Separated same-boot plugin restart recovery from cold-boot auto-connect by recording the Linux boot ID in runtime state.
- Added nftables ownership markers and refusal-to-delete behavior for an unrelated table named `vdeck`.
