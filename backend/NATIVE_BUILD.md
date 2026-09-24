# Native binary build / Сборка нативных бинарников

## Premium API helper

`backend/premium` builds the original `premium-api` helper using pinned Go 1.25.14,
CGO disabled and linux/amd64 target. It only performs HTTPS API requests and exits;
it is not a VPN daemon. See `premium/BUILD.md` for build instructions and provenance.

## Xray 26.3.27 (local preview)

Unlike the existing AWG/WG/OpenVPN source builds below, Xray uses the official
Linux amd64 release prebuilt with Go 1.26.1. The exact archive URL/SHA-256, executable
SHA-256 and source commit are pinned in versions.json. Docker retrieves and verifies
that archive; it does not claim to reproduce Xray's upstream build. No Docker is needed
on Steam Deck. The local release builder includes bin/xray with executable mode and
the source archive includes research/xray-core. Run verify_release and verify_source
after packaging; Linux execution and physical TUN behavior still need a Deck test.

## Русский

Docker используется только сопровождающими разработчиками и GitHub Actions для воспроизводимой сборки пяти Linux x86-64 компонентов. Он не запускается V-Deck, не входит в установочный ZIP и не требуется пользователю или Steam Deck.

```text
docker build -f backend/Dockerfile --target binaries --output type=local,dest=release/native .
python scripts/elf_audit.py release/native/*
```

Рецепт закрепляет digest Dockerfile frontend и Alpine, Go archive по SHA-256, точные upstream tags и commits из `versions.json`. Сборка проверяет каждый commit до применения локальных патчей. Go-компоненты собираются для `GOOS=linux`, `GOARCH=amd64`; C-компоненты и OpenVPN статически линкуются с musl, а OpenVPN — со статическими wolfSSL и libcap-ng.

`amneziawg-go-version.patch` исправляет только отображаемую upstream-версию. Патчи `amneziawg-tools-bundled-uapi.patch` и `wireguard-tools-bundled-uapi.patch` заставляют generic Linux build использовать закреплённые UAPI из соответствующих source tags вместо более старого заголовка ядра сборочной системы. `openvpn-static-autotools.patch` задаёт `-all-static` непосредственно для OpenVPN executable. `wolfssl-openvpn-cmake.patch` и `openvpn-static-cmake.patch` являются материалами альтернативной Zig/CMake cross-сборки, использованной для bundled release files.

Docker CI и bundled binaries могут иметь разные byte hashes из-за разных компиляторов и build paths. Для bundled-файлов авторитетны SHA-256 в `versions.json`; CI отдельно проверяет их ELF-структуру, архитектуру, отсутствие interpreter/`DT_NEEDED` и manifest hashes.

## English

Docker is used only by maintainers and GitHub Actions to reproducibly build five Linux x86-64 components. V-Deck never runs Docker, the installer ZIP does not contain it, and neither users nor Steam Deck need Docker.

```text
docker build -f backend/Dockerfile --target binaries --output type=local,dest=release/native .
python scripts/elf_audit.py release/native/*
```

The recipe pins the Dockerfile frontend and Alpine by digest, verifies the Go archive by SHA-256, and checks exact upstream tags and commits from `versions.json` before applying local patches. Go components target `GOOS=linux`, `GOARCH=amd64`; C components and OpenVPN are statically linked with musl, with OpenVPN using static wolfSSL and libcap-ng.

`amneziawg-go-version.patch` changes only the stale upstream version string. The `amneziawg-tools-bundled-uapi.patch` and `wireguard-tools-bundled-uapi.patch` files make generic Linux builds use the pinned UAPI from each source tag instead of an older build-host kernel header. `openvpn-static-autotools.patch` applies `-all-static` directly to the OpenVPN executable target. `wolfssl-openvpn-cmake.patch` and `openvpn-static-cmake.patch` are inputs for the alternative Zig/CMake cross-build used for the bundled release files.

Docker CI and bundled binaries may have different byte hashes because they use different compilers and build paths. SHA-256 values in `versions.json` are authoritative for bundled files; CI independently verifies their ELF structure, architecture, absence of an interpreter/`DT_NEEDED`, and manifest hashes.
