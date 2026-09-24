# Premium helper: build and provenance

`premium-api` is an independent V-Deck component written in Go using its standard
library. It is a separate process, not a VPN daemon. Its component version is
independent of the plugin version. No Go installation is required on Steam Deck.

Build using the Go version pinned in `backend/versions.json`:

```sh
cd backend/premium
go test ./...
go vet ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags='-s -w' -o ../../bin/premium-api .
```

The ordinary test suite uses synthetic inputs and mocked transports; it does not
use real subscriptions or contact the provider. Production credentials are never
test fixtures. Do not disable TLS verification or print request/response payloads.

Compatibility reference: the publicly available
[Amnezia client source](https://github.com/amnezia-vpn/amnezia-client/tree/7d4f3e0f5090b74903609179653d1f669d2ad08a).
No client source is copied or linked into this helper. V-Deck is not an official
Amnezia application and does not claim a guaranteed third-party API contract.
Original helper code follows the repository license; preserve the Go notice in
`licenses/Go-BSD-3-Clause.txt`. See `THIRD_PARTY_NOTICES.md` for bundled components.
