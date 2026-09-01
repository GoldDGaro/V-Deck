# Third-party notices and license audit

This audit applies to V-Deck 0.1.0. V-Deck's PolyForm license covers only original V-Deck code. Every component below keeps its own license. Source URLs identify the exact upstream; the release's adjacent corresponding-source archive contains the source used for bundled GPL executables, build recipes, and local build patches.

## Shipped native executables

| Project | Pinned version | License | Use / linking | Binary and source obligations | Included notice |
|---|---:|---|---|---|---|
| [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) | `v3.1.20260828` | MIT | Separate bundled userspace AWG executable, static Go binary | Preserve MIT notice; source offered for reproducibility | `licenses/amneziawg-go-MIT.txt` |
| [amneziawg-tools](https://github.com/amnezia-vpn/amneziawg-tools) | `v3.1.20260812` | GPL-2.0-only | Separate bundled `awg` executable, static musl | GPL copy plus complete corresponding source/build scripts must accompany binaries | `licenses/amneziawg-tools-GPL-2.0.txt` |
| [wireguard-go](https://git.zx2c4.com/wireguard-go/) | `0.0.20250522` | MIT | Separate bundled WireGuard userspace fallback, static Go binary | Preserve MIT notice; source offered for reproducibility | `licenses/wireguard-go-MIT.txt` |
| [wireguard-tools](https://git.zx2c4.com/wireguard-tools/) | `v1.0.20260223` | GPL-2.0-only | Separate bundled `wg` executable, static musl | GPL copy plus complete corresponding source/build scripts must accompany binaries | `licenses/wireguard-tools-GPL-2.0.txt` |
| [OpenVPN](https://github.com/OpenVPN/openvpn) | `v2.7.6` | GPL-2.0-only with upstream exceptions | Separate bundled `openvpn` executable; statically linked to wolfSSL; LZO/LZ4/PKCS#11/DCO disabled | Whole executable is distributed under GPL-2.0; corresponding OpenVPN and linked wolfSSL source/build material accompanies it | `licenses/OpenVPN-GPL-2.0.txt` |
| [wolfSSL](https://github.com/wolfSSL/wolfssl) | `v5.9.2-stable` | GPL-3.0, with explicit election of GPL-2.0 when combined with OpenVPN | Statically linked only into bundled OpenVPN | V-Deck elects GPL-2.0 for this OpenVPN combination under wolfSSL's written exception; ship COPYING, exception, and corresponding source | `licenses/wolfSSL-GPL-3.0.txt`, `licenses/wolfSSL-LICENSING.txt` |

The GPL programs communicate with V-Deck through normal process execution, standard input/output, local management sockets, and Linux networking interfaces. They are not imported or linked into the original Python/TypeScript V-Deck program. This separation does not remove the GPL obligations for the executable files themselves; the binary release and matching `V-Deck-v0.1.0-source.zip` must remain available together.

OpenSSL is not bundled or linked. OpenVPN is deliberately built with wolfSSL. OpenVPN's OpenSSL exception remains in its upstream COPYING file but is not the basis of this build.

## Runtime frontend and host components

| Project | Version | License | Usage type | Redistribution / compatibility |
|---|---:|---|---|---|
| [Decky Loader API](https://github.com/SteamDeckHomebrew/loader-api) | `1.1.3` | LGPL-2.1 | Decky-provided runtime API imported by the frontend | License included. API is provided by the host; V-Deck does not replace its license. |
| [Decky UI](https://github.com/SteamDeckHomebrew/decky-frontend-lib) | `4.12.0` | LGPL-2.1 | Frontend component library / host integration | License included; bundled output remains replaceable at source/build level. |
| [React Icons](https://github.com/react-icons/react-icons) | `5.7.0` | MIT (individual icon sets also retain upstream notices) | Selected icon code included by the frontend bundle | MIT notice included. |
| [tslib](https://github.com/microsoft/tslib) | `2.8.1` | 0BSD | TypeScript runtime helpers if emitted by the bundle | 0BSD notice included. |
| React / Steam client UI runtime | Host-provided | MIT / Valve terms as applicable | Peer runtime supplied by Steam/Decky, not shipped in the ZIP | Not redistributed by V-Deck. |
| Python 3 standard library | SteamOS/Decky-provided | PSF-2.0 and component notices | Backend interpreter/runtime, not embedded | Not redistributed by V-Deck. |
| Linux `ip`, `nft`, `resolvectl`, ping, kernel WireGuard | SteamOS-provided | Distribution/component terms | Invoked host commands and kernel API | Not redistributed by V-Deck. |

## Build and test dependencies (not shipped)

The exact JavaScript graph is locked in `pnpm-lock.yaml`. Direct build/test inputs include `@decky/rollup 1.0.2` (LGPL-2.1), Rollup 4.63.1 (MIT), TypeScript 5.9.3 (Apache-2.0), ESLint 9.39.5 (MIT), Prettier 3.9.6 (MIT), Vitest 4.1.11 (MIT), and the TypeScript ESLint packages 8.68.0 (MIT). They are not copied into the install ZIP.

Native build inputs are Go 1.25.14 (BSD-3-Clause), Zig 0.15.2 (MIT), CMake 4.1.0 (BSD-3-Clause), Ninja 1.13.0 (Apache-2.0), Git, and Alpine Linux packages used by `backend/Dockerfile`. They are build tools, not runtime payloads. Python verification uses only the standard library plus Ruff and mypy in development/CI; V-Deck has no third-party Python runtime package dependency.

## Reference project

[MrWaip/vpn-deck](https://github.com/MrWaip/vpn-deck) is BSD-3-Clause. V-Deck did not copy its implementation. The migration module independently recognizes its documented/user-visible storage location and performs copy-only import; therefore its source is not included in the plugin. Its upstream repository was reviewed solely as a behavioral reference.

## Source-distribution checklist

Anyone redistributing `V-Deck-v0.1.0.zip` should also provide the unmodified license files and the adjacent `V-Deck-v0.1.0-source.zip` from the same release. The source archive must include exact tagged sources, the wolfSSL CMake OpenVPN recipe backport, OpenVPN static-build patch, Docker/build scripts, and the V-Deck source corresponding to the binaries. Do not apply the PolyForm terms to third-party source.
