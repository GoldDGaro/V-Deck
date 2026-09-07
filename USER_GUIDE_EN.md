# V-Deck 0.1.0 — user guide

[Русский](USER_GUIDE_RU.md) · [Project overview](README.md#english) · [Validation status](VALIDATION.md)

V-Deck manages VPN profiles from Steam Deck Gaming Mode. It does not provide a VPN service, subscription or server: obtain a configuration from your provider or server administrator. This is a preview; an implemented feature is not a promise of compatibility with every network.

## 1. Requirements and precautions

- Steam Deck with SteamOS, Decky Loader and working normal internet access.
- Physical user testing confirms AmneziaWG `.conf` and native `.vpn`. WireGuard and OpenVPN have not yet been physically validated.
- Keep a safe backup of your original profiles and credentials. Never publish them.
- Turn off other VPN clients and their auto-start for the initial test. Coexistence with VPN Deck or other network plugins is unverified; do not delete their profiles.
- V-Deck needs elevated privileges to manage interfaces, routes, DNS and firewall. Install only from a trusted source.

Docker and separate OpenVPN/WireGuard/AmneziaWG packages are not required. Linux x86-64 clients are bundled, and Decky supplies Python. Do not disable SteamOS read-only protection to install development packages for V-Deck.

## 2. Installation

1. If necessary, install Decky using its [official instructions](https://github.com/SteamDeckHomebrew/decky-loader#-installation) from Desktop Mode. Choose the stable branch for normal use and return to Gaming Mode.
2. Download **V-Deck-v0.1.0.zip** from the [new release](https://github.com/GoldDGaro/V-Deck/releases/tag/v0.1.0-preview.2) to Downloads on the Deck. `V-Deck-v0.1.0-source.zip` and GitHub's automatic `Source code` archives are not installers.
3. Open `…` → Decky (plug icon) → Decky settings. Enable Developer Mode if the Developer page is not available.
4. In Developer, choose third-party plugin installation from ZIP, select the downloaded file and confirm. Exact labels depend on Decky version/language. Remote debugging is not needed.
5. Wait for installation and open V-Deck. Restart Decky or the device if it does not appear.

The Developer/ZIP installation route is documented in [Decky's official source](https://github.com/SteamDeckHomebrew/decky-loader/blob/main/frontend/src/components/settings/pages/developer/index.tsx). V-Deck does not claim to be listed in the Decky Store.

Optional download verification in Konsole, from Downloads:

```sh
sha256sum V-Deck-v0.1.0.zip
```

Compare against `SHA256SUMS.txt` from **the same release**. Preview builds currently share the filename `V-Deck-v0.1.0.zip`; the filename alone does not identify the build.

## 3. Add a VPN

1. Place your configuration in a local folder, for example `/home/deck/Downloads`.
2. Open V-Deck → **Add VPN**.
3. Choose **AmneziaWG**, **WireGuard** or **OpenVPN**. You select the protocol; `.conf` alone does not distinguish AWG from WG.
4. Choose the configuration file.
5. After validation, enter a non-empty connection name. Fill in any requested OpenVPN username, password or private-key passphrase.
6. Press **Import**. Selecting a file alone does not import it. The button is disabled for an empty name.
7. The expected result is a return to the main list with the new profile. If an error appears, record its stable code.

| Protocol | Format | Limitations |
| --- | --- | --- |
| AmneziaWG | `.conf`, `.vpn` | Native exports must contain a supported `amnezia-awg`/`amnezia-awg2` container. Not every Amnezia export is AWG. No `vpn://` paste UI. |
| WireGuard | `.conf` | Kernel-first, bundled userspace fallback. `Table=off` and custom routing tables are unsupported. |
| OpenVPN | `.ovpn` | Requires local `route`/`redirect-gateway` and `dhcp-option DNS`; server-push-only routing/DNS is unsupported. |

OpenVPN relative certificate/key files must be available beside the configuration within the permitted directory structure. Command hooks, plugins, arbitrary executable/output paths and unsupported options are intentionally rejected. Request a compatible profile instead of weakening validation. Legacy OpenSSL/Blowfish profiles may be incompatible with bundled wolfSSL.

## 4. Connect and manage profiles

1. Leave Kill Switch off for the first test.
2. Turn on a profile and wait for **Connected** before treating the tunnel as ready.
3. Check the intended game/site and diagnostics. One successful request is not proof that all traffic is protected.
4. Turn the profile off, wait for **Disconnected**, and check normal internet access.

V-Deck is designed for one active VPN. Switching profiles first stops the previous connection; do not run another VPN client concurrently. Failed Connect should not delete a saved profile.

- **Rename** changes its display name.
- **Delete** removes the stored profile and credentials after confirmation. Disconnect first. The original file in Downloads is a separate copy.
- Active-profile ping updates periodically; inactive profiles display their last saved value. This is not continuous monitoring of inactive servers, nor necessarily the game-server latency.
- Settings offer automatic, Russian and English language selection.

## 5. Auto-connect and recovery

Enable **Auto-connect**, connect the desired profile, and leave it ON before rebooting. V-Deck attempts to restore desired ON after startup, including bounded retries while the physical network becomes available.

Manual OFF is remembered and should not be undone by auto-connect. Unexpected-disconnection recovery is part of the lifecycle, not a separate Auto Recovery switch in the UI. Retries are limited; `RECOVERY_EXHAUSTED` means attempts ran out, not that the connection succeeded.

User feedback confirms reboot and Wi-Fi OFF/ON with auto-connect and KS. This does not establish roaming across different networks, suspend/resume or every DHCP/DNS configuration.

## 6. Kill Switch (KS)

KS is disabled by default. Read and confirm the warning before first enabling it. It is intended to block ordinary outbound IPv4/IPv6 after an established tunnel unexpectedly fails, while recovery runs.

- Initial manual Connect applies KS after basic checks: this is **not** a block on all traffic from device power-on.
- Recovery prepares firewall rules before checking the replacement tunnel. Necessary control traffic and VPN endpoints have allowances.
- Internet may remain blocked if recovery fails; this is the purpose of KS.
- **Manual VPN OFF removes V-Deck's owned restrictions**, deliberately allowing ordinary internet. KS is not a permanent internet ban while VPN is off.
- Do not assume comprehensive IPv6/DNS leak protection without testing your network.

## 7. Diagnostics and external IP

Open **Diagnostics** for a profile. Interface, route, DNS, handshake/traffic status and error codes help locate failures. Missing data is not a successful check. Export saves a report to the path shown by the UI.

To compare external IPv4:

1. Turn V-Deck off and wait for disconnection.
2. Press **Check external IPv4 now** in diagnostics to capture the OFF sample.
3. Connect, wait for Connected, and run the check again.
4. Compare addresses, timestamps and active-profile labels. Samples are historical, not automatically refreshed, and disappear when the backend restarts.

The implementation uses Python `urllib.request`, `ssl` and `ipaddress`: HTTPS to `api.ipify.org`, with `ipv4.icanhazip.com` as fallback. The service sees the caller's public IP, not VPN configuration, keys or passwords. Certificate/hostname verification is mandatory; Linux explicitly loads system trusted CAs. Requests happen only on click, not on opening diagnostics or exporting a report. Full samples stay in memory and are not added to logs/exports.

Requests follow current system routing without bypassing KS. Another VPN or split routing can affect results; “V-Deck OFF” does not mean every other VPN is off. Equal or different IPv4 addresses alone do not prove or disprove all leaks. IPv6 and DNS require separate testing.

**The latest IP TLS fix still needs physical Steam Deck validation.** Earlier device logs proved certificate rejection, but did not identify the exact underlying chain cause.

## 8. Troubleshooting

| Code/symptom | Action |
| --- | --- |
| `CONFIG_FILE_NOT_ACCESSIBLE` | Select a local file accessible to Decky, such as one in Downloads. Do not make secrets world-readable with `chmod 777`. |
| `IMPORT_FRONTEND_FAILED` | Record the code, stage and safe import debug log. Do not publish the profile. |
| `ENDPOINT_ROUTE_INVALID` | Check Wi-Fi and ordinary connectivity. If KS blocks access, manually turn VPN off and reconnect after the network is ready. |
| `VPN_TRAFFIC_UNCONFIRMED` | Traffic through the tunnel has not been confirmed. Inspect route/DNS/handshake diagnostics and server availability. |
| `RECOVERY_EXHAUSTED` | Manually turn the profile off, wait for cleanup, restore the underlying network and retry. |
| `EXTERNAL_IP_TLS_FAILED` | Check device date/time; collect `external IP TLS trust` and `verify_code` log lines. Do not disable certificate verification. |
| `EXTERNAL_IP_CA_UNAVAILABLE` | System CAs could not be loaded. Report the code and SteamOS version; do not install random certificates. |
| `EXTERNAL_IP_UNAVAILABLE` | Neither provider returned a usable response: DNS, network or provider availability may be involved. This diagnostic error alone does not prove VPN failure. |

If networking is blocked, first use manual OFF. Only as a local emergency measure when OFF fails and you deliberately want direct internet: enter Desktop Mode, inspect `sudo nft list table inet vdeck` to confirm V-Deck ownership, then delete **only that table**:

```sh
sudo nft delete table inet vdeck
```

This removes KS protection. It is not complete interface/route cleanup or a fix for the underlying issue. Never flush the global firewall ruleset. Collect diagnostics if trouble continues.

Report release tag/hash, SteamOS/Decky versions, protocol/format, KS/auto-connect settings, reproduction steps and error code. `vdeck.log` lives in Decky's `DECKY_PLUGIN_LOG_DIR`; the exact path depends on installation. Technical logs can contain paths, network addresses and profile names. Review and redact before sharing, even after automated sanitization. Never put keys, passwords, configurations or raw log archives into public Issues.

## 9. Update and uninstall

Back up original profiles/credentials, manually disconnect, and check normal internet before updating. Install the new ZIP using the same steps, without first deleting profiles. Settings are stored separately from plugin code, but retention across every Decky reinstall path is not guaranteed; keep backups.

Before uninstalling, turn VPN and KS off and verify internet, then remove V-Deck in Decky settings. Decky may retain plugin-created settings/data; uninstalling code does not erase every secret. Do not delete the entire `homebrew` directory or another application's network settings. Remember original configurations in Downloads and backups.

## License

Original code uses [PolyForm Noncommercial 1.0.0](LICENSE): publicly available source, with separate permission required for commercial use. Third-party components retain their [own licenses](THIRD_PARTY_NOTICES.md); corresponding source accompanies the installer. Public visibility is not a change to MIT/GPL or Decky Store approval.
