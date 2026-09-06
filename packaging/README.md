# Packaging (WP-16)

Reproducible install references for the sentinel CLI. Real release
artifacts come from tag-triggered GoReleaser builds
(`.github/workflows/release.yml` + `.goreleaser.yaml`).

## Homebrew

```bash
brew tap Ferrum-Sidereum/sentinel
brew install sentinel
```

Reference formula: `homebrew/sentinel.rb`. On each tag, GoReleaser
regenerates it with the release version and sha256. The committed copy
uses `0.0.0` + `REPLACE_WITH_RELEASE_SHA256` placeholders on purpose.

## Scoop (Windows)

```powershell
scoop bucket add sentinel https://github.com/Ferrum-Sidereum/scoop-sentinel
scoop install sentinel
```

Reference manifest: `scoop/sentinel.json`, same placeholder convention.

## Verify a release

```bash
sha256sum -c checksums.txt
cosign verify-blob \
  --cert-identity-regexp 'https://github.com/Ferrum-Sidereum/sentinel.*' \
  --cert-oidc-issuer https://token.actions.githubusercontent.com \
  --cert checksums.txt.pem \
  --signature checksums.txt.sig \
  checksums.txt
```

## ldflags contract

CI stamps the binary with:

```
-X main.version={{.Version}} -X main.commit={{.ShortCommit}} -X main.date={{.CommitDate}}
```

`sentinel version` prints `sentinel <version> (commit <sha>, built <date>, <os>/<arch>)`.
Unstamped local builds report `dev / none / unknown`.
