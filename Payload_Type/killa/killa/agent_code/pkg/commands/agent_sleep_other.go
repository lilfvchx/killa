//go:build !windows

package commands

import (
	"time"
)

// AgentSleep performs a sleep, using standard time.Sleep on non-Windows platforms.
func AgentSleep(d time.Duration) {
	time.Sleep(d)
}
