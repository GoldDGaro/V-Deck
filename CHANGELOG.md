# Changelog

## 0.1.0-preview.2 — 2026-09-07

- Publish the accumulated local import/runtime/recovery fixes below as a public preview of plugin version 0.1.0. Preserve the old v0.1.0 tag and release for history.
- Add Russian and English user guides covering installation, updates, profile import, connection controls, auto-connect, Kill Switch, diagnostics, external IPv4 privacy, recovery and removal. Include both guides and the validation matrix in the install/source archives and require them during verification.
- Update project descriptions and distinguish user-reported physical AmneziaWG results from mocked WireGuard/OpenVPN coverage. External-IP host-CA loading is implemented, but its latest fix remains unverified on Steam Deck.
- Local runtime baseline: 215 backend and 31 frontend tests pass. Public visibility does not change the PolyForm Noncommercial 1.0.0 license or third-party license obligations.

The entries below describe the local development history now included in this preview. Their earlier unpublished/awaiting-test labels refer to the state at that time; [VALIDATION.md](VALIDATION.md) records the current evidence.

## External IPv4 TLS follow-up — 2026-09-06 (local, unpublished)

- New physical logs show `SSLCertVerificationError` from both IP services while VPN is CONNECTED; the previous log did not capture the certificate verification code, so the exact chain rejection cause remains unconfirmed.
- Load the Linux host CA bundle explicitly for IP checks instead of relying on frozen Python/OpenSSL default locations. Keep mandatory chain/hostname verification; do not enable inherited TLS key logging or modify global environment, system certificates, VPN or firewall.
- Separate missing-CA and certificate-rejection error codes with RU/EN messages. Log CA source/count and numeric verification code safely. Add tests for frozen environment isolation, missing/broken/fallback CA files and rejection without insecure retries.
- User feedback reports reboot auto-connect+KS, Wi-Fi recovery+KS and button layout now working on physical Deck. These runtime paths are unchanged by this TLS-only follow-up.

## Physical Steam Deck follow-up — 2026-09-06 (local, unpublished)

- Physical feedback confirms base AmneziaWG `.conf`/native `.vpn` import, Connect and real game-server traffic in the previous candidate. WireGuard and OpenVPN still have no physical acceptance results.
- Fix cold-boot auto-connect running before a physical route exists: bounded background retries preserve desired ON and network events can resume an exhausted initial attempt. Manual OFF and manual profile switching cancel pending retries.
- Fix Wi-Fi recovery with Kill Switch: permit the deterministic upcoming owned tunnel before backend health probes, including after cleanup/endpoint refresh. Do not grant an allowance to an unjournaled pre-existing interface. Retain strict protection through recovery; manual OFF removes owned rules.
- Add explicit device external IPv4 checks before/after VPN with timestamp, active-profile label, memory-only samples and stable errors. Use verified HTTPS to ipify with icanhazip fallback; no ambient proxy, redirects, config upload, automatic lookup or Kill Switch bypass. Discard samples if the network changes mid-request.
- Stack profile action buttons vertically with full-width wrapping styles for Russian labels. Coalesce repeated native errors with counts; log health failure flags and actual firewall interface safely.
- Add regression coverage at manager, simulated Linux/nft, RPC, HTTPS transport and rendered UI boundaries. These fixes still need a new physical Steam Deck test; no native binaries or GitHub state were changed.

## Independent local runtime audit — 2026-09-06 (unpublished)

- Reproduced previously untested OpenVPN import escapes (nested config, alternate executable/provider/file directives); require reviewed client options, validate DNS/routes, preserve external tls-auth direction and detect legacy encrypted keys. Reject multiline credentials and unsupported WG Table modes explicitly.
- OpenVPN now journals PID before startup waits, frames fragmented management replies and CRLF correctly, and uses V-Deck-owned routes with route-noexec. Verify interface, routes, traffic and DNS before Connected, including after Kill Switch. Full server-push-only routing/DNS is explicitly unsupported in this candidate; use local route/redirect-gateway and dhcp-option DNS directives.
- Make Kill Switch settings transactional, require warning acknowledgement in the backend, verify a live toggle and roll back failure; OFF removes owned rules even after recovery exhaustion.
- Attempt process/interface/route cleanup even if DNS restoration fails during initialization. Ignore stale health results from an earlier session; refuse late recovery of a manually deleted/off profile. Bound endpoint DNS lookup time.
- Normalize equivalent full-tunnel route halves and avoid duplicate route additions. Normalize interface address comparison. Diagnostics no longer query an inactive profile through another profile's active tunnel and bind ping to the VPN interface.
- Native stdout/stderr no longer bypasses sanitization into raw files: bounded readers log only recognized literal diagnostics, with stage/exit/exception evidence logged separately. Unknown native payloads are deliberately withheld. Diagnostics RPC rejection clears UI busy state; snapshot failure does not hide the original Connect error.
- Add independent parser/settings/cleanup/race regressions, OpenVPN mocked lifecycle and management-framing tests, real child-output privacy test and rendered frontend failure tests. Existing local changes retained; no GitHub publication or native binary changes. Physical Steam Deck acceptance is still required.

## Local first-working-candidate — 2026-09-03 (unpublished)

- Restore pre-PyInstaller loader paths for host utilities and use a separate environment for independently bundled VPN executables. Apply the host environment to the NM monitor as well; classify loader errors separately from inactive services.
- Resolve native Amnezia DNS placeholders from exported dns1/dns2; normalize and validate WG/AWG network fields before runtime. Preserve AWG options and support inline comments. Old imports with unresolved placeholders require re-import, not guessed DNS or profile deletion.
- Add sanitized exception chains with file/function/line and no locals, source lines or arbitrary exception messages. Preserve stage/error/exit/cleanup diagnostics and capture bounded NM monitor stderr.
- Select a physically routable hostname endpoint instead of requiring routes to all A/AAAA answers. Retry leftover owned firewall cleanup before another Connect. Attempt all orphan cleanup stages; do not delete interfaces merely because their names match stored profiles.
- Serialize Delete against Connect and cancel recovery when unloading the service. Extend mocked end-to-end and failure/retry matrices to native AWG .vpn, AWG .conf, kernel WG and userspace WG, including dual-stack, Kill Switch, DNS restore and manual OFF.
- Native binaries remain unchanged. This candidate is locally verified; physical Steam Deck networking and Gaming Mode acceptance are still required.

## Local runtime/DNS follow-up — 2026-09-02 (unpublished)

- Repeat active traffic and DNS verification after enabling Kill Switch, before publishing Connected, including recovery. Periodic health checks detect DNS outages as well as tunnel failures.
- Verify unchanged DNS for profiles without `DNS=`; allow known direct system resolvers only on verified routes, and require explicit VPN DNS when a local stub/NSS path or underlay route cannot be proven safe. Do not silently invent a public resolver.
- Add owned, metric-qualified DNS host routes when LAN routes shadow explicit VPN DNS; reject endpoint/DNS host-route conflicts. Resume recovery after Wi-Fi restoration following retry exhaustion; ignore own interface events and restart the NM device monitor after it exits.
- Complete safe cleanup/stage logging and command exit diagnostics; withhold config-tool output that may contain raw keys, and pin command locale for deterministic cleanup error handling.
- Physical Steam Deck feedback confirms AWG import, foreground process, UAPI and setconf; the next observed failure is DNS application, not AWG process startup.
- Select DNS by runtime capabilities: active resolved stub/per-link DNS or NetworkManager `dns=default` with an owned, nonpersistent DNS-contributor profile. Verify resolver readback, route to DNS and an interface-bound DNS answer; reject unsupported managers explicitly. No system configuration files or physical connection profiles are rewritten.
- Journal DNS and every route before mutation; preserve cleanup ownership and the original error on partial failure/cancellation. Keep profiles intact, diagnose unreadable metadata instead of returning an empty list, and log explicit delete RPC calls separately.
- Require interface addresses, effective routes and an interface-bound traffic probe before Connected. Protect IPv4-only full tunnels from IPv6 bypass; remove the kill switch's blanket established-flow exemption. Filter self-induced NetworkManager recovery triggers and retain manual OFF after recovery exhaustion.
- Added local mocked Linux service-to-network integration tests, failure/retry/profile-preservation matrices for AWG, kernel WG and userspace WG, and rendered UI failure/manual-OFF tests. Native binaries unchanged. Real SteamOS resolver integration and live VPN traffic still require physical retesting.

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
- Improved the import boundary by enabling Decky's real `root` flag, preserving both file-picker paths across RPC, validating backend accessibility, and surfacing stable import error codes. Physical testing subsequently confirmed validation but still found no import RPC; these changes alone did not resolve the blocker.
- Local follow-up (2026-09-02): preserve the pending picker and import form across Decky's QAM visibility gate with `alwaysRender`; add rendered click-flow regression tests, duplicate-submit protection, pre-RPC error handling, and an allowlisted frontend import log in the UI and `vdeck.log`. The QAM state-loss defect is reproduced locally; resolution of the reported physical-device click failure still requires a Steam Deck retest.
- Subsequent physical Steam Deck feedback confirmed that import now works. The next reported blocker is userspace AmneziaWG startup.
- Local userspace-startup fix: run both bundled AmneziaWG and WireGuard fallback with `--foreground` and `WG_PROCESS_FOREGROUND=1`; persist/check/reap the exact owned process, require TUN + UAPI + successful setconf before networking, and log startup/exit diagnostics without config contents. AmneziaWG remains userspace-only and WireGuard remains kernel-first. Native binaries are unchanged; VPN operation still needs a physical Steam Deck retest.
