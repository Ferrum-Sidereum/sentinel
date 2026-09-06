package main

import (
	"fmt"
	"runtime"
)

// Set via -ldflags at release time; see .goreleaser.yaml and
// .github/workflows/release.yml for the exact flags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func cmdVersion() {
	fmt.Printf("sentinel %s (commit %s, built %s, %s/%s)\n", version, commit, date, runtime.GOOS, runtime.GOARCH)
}
