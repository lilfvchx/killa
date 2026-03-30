//go:build !windows

package commands

import (
	"time"
)

// AgentSleep is a wrapper around time.Sleep on non-Windows platforms.
func AgentSleep(d time.Duration) {
	if d <= 0 {
		return
	}
	time.Sleep(d)
}
