# Contributing

Contributions are accepted only when the contributor has the right to submit them under V-Deck's PolyForm Noncommercial 1.0.0 terms. Do not copy code from a dependency or reference project into V-Deck without recording its provenance and license.

Run all Python/frontend checks from the README, add parser/security regression tests for imported-input changes, and never weaken ownership-scoped cleanup. New protocols implement `VPNBackend` and register in one place. A change that requires a new privileged command must document its exact arguments, ownership marker, cleanup behavior, and secret-handling implications.

Do not commit real VPN profiles, credentials, endpoints, private/public keys, diagnostic exports, build caches, `node_modules`, or generated release ZIPs.
