# Native binary build

`Dockerfile` builds five x86_64 Linux executables on pinned Alpine 3.22.1. Go archives are checksum-verified; upstream repositories are checked out at the exact tags/commits in `versions.json`. C tools and OpenVPN are statically linked against musl. OpenVPN uses wolfSSL's official `--enable-openvpn` compatibility recipe; LZO, LZ4, PKCS#11, DCO, PAM plugin, systemd, and SELinux integrations are disabled because Steam Deck receives one self-contained plugin executable.

```text
docker build -f backend/Dockerfile --target binaries --output type=local,dest=release/native .
python scripts/elf_audit.py release/native/*
```

The Windows development build used pinned Zig 0.15.2 for cross-compilation and the included CMake patches. The Docker recipe uses upstream autotools integration where available. Both paths compile the same tagged source and feature set; byte hashes can differ because compilers/build paths differ. Release hashes are authoritative in `versions.json`.

The amneziawg-go tag contains a stale upstream version string; `amneziawg-go-version.patch` changes only the reported string to the checked-out tag. `wolfssl-openvpn-cmake.patch` backports the integration block already present upstream after 5.9.2, matching the tag's existing `./configure --enable-openvpn` recipe. `openvpn-static-cmake.patch` removes DCO-only dependencies and uses the installed static wolfSSL CMake target for the Zig cross-build.
