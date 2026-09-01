# Security policy

## Threat model and boundaries

V-Deck treats every imported configuration as hostile. Import validation must not execute configuration directives, follow symlinks outside the selected directory, copy absolute/traversal paths, or write to paths selected by the profile. OpenVPN hooks, plugins, user-supplied management settings, logging/output files, and other command-capable directives are rejected.

The plugin runs with elevated privileges. Network cleanup is therefore ownership-scoped:

- interface names must match `vdeck-[0-9a-f]{8}`;
- routes are created and deleted with protocol marker `186`;
- firewall rules live only in `table inet vdeck`, whose ownership comment is verified before replacement or deletion;
- DNS is changed and reverted per V-Deck interface;
- processes are stopped only when PID, executable, and Linux process start time still match.

Secrets live in connection credential/config files with mode `0600` under directories with mode `0700`. They are not stored in shared metadata or passed on process command lines. Log and report sanitizers redact WireGuard keys, OpenVPN inline keys/certificates, passwords, tokens, and common credential forms. Public IPs are masked in exported reports.

## Reporting a vulnerability

Do not post credentials, full diagnostic archives, VPN profiles, private keys, or unredacted public endpoints in a public issue. Reproduce with a synthetic profile when possible and include V-Deck/Decky/SteamOS versions, protocol, operation, and the stable error code.

Until a project security contact is published, report privately to the release maintainer through the repository's private security-reporting channel. If no private channel exists, publish only a minimal notification asking the maintainer to establish one.

## Operational recovery

If networking is unexpectedly blocked, manually switch the active connection OFF. V-Deck deletes `inet vdeck` only when its ownership marker is present, together with other owned tunnel resources. As a last-resort local recovery from Desktop Mode:

```text
sudo nft delete table inet vdeck
```

Do not flush the global ruleset.
