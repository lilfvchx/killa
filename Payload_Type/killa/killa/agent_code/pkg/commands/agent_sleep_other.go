//go:build !windows

package commands

import (
	"time"
)

// AgentSleep wraps time.Sleep with evasive logic (no-op on non-Windows)
func AgentSleep(d time.Duration) {
	time.Sleep(d)
}
