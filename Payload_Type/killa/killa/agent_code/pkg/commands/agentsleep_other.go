//go:build !windows

package commands

import (
	"time"
)

// AgentSleep performs a standard sleep on non-Windows platforms.
func AgentSleep(d time.Duration) {
	time.Sleep(d)
}
