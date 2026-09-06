// Stub MCP server for broker-mode e2e: echoes SENTINEL_BROKER_URL presence
// on initialize, never prints secret values.
package main

import (
	"bufio"
	"fmt"
	"os"
)

func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	for sc.Scan() {
		line := sc.Text()
		hasBroker := os.Getenv("SENTINEL_BROKER_URL") != ""
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"echo":%q,"broker":%v}}`+"\n", redact(line), hasBroker)
		w.Flush()
	}
}

func redact(s string) string {
	if len(s) > 64 {
		return s[:64]
	}
	return s
}
