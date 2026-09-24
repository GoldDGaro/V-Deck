# Corresponding source availability

The local Xray preview also includes the exact MPL-2.0 Xray-core v26.3.27 source
in `third_party_src/xray-core`. Its executable is the verified upstream Linux amd64
release, not a local source build; provenance and hashes are in backend/versions.json.

The installable V-Deck 0.1.0 archive contains GPL-licensed separate executables and one GPL-licensed static combination. Complete corresponding source and build material are distributed as the adjacent release asset:

`V-Deck-v0.1.0-source.zip`

Keep that asset available with `V-Deck-v0.1.0.zip`. It contains the exact tagged upstream source used for amneziawg-tools, wireguard-tools, OpenVPN, and wolfSSL, along with V-Deck source, the pinned Docker build recipe, patches, toolchain metadata, and build instructions. The third-party source retains its original license; PolyForm applies only to original V-Deck code.
