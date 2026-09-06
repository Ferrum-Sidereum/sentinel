# Sentinel

## Toolchain

Minimum Go version: **1.27.0** (`toolchain go1.27.0` in `go.mod`; newer toolchains auto-fetch it).

## Install (no Go toolchain needed)

Grab a release binary from GitHub Releases (`sentinel_<version>_<os>_<arch>.tar.gz`/`.zip`), unpack, verify, and check the version:

```bash
sha256sum -c checksums.txt
./sentinel version
```

Homebrew and Scoop references live in [`packaging/`](packaging/README.md):

```bash
brew tap Ferrum-Sidereum/sentinel && brew install sentinel
```

```powershell
scoop bucket add sentinel https://github.com/Ferrum-Sidereum/scoop-sentinel
scoop install sentinel
```

Building from source still works (`go install ./cmd/sentinel`) but is no longer required.
