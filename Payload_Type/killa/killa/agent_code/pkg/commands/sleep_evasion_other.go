//go:build !windows

package commands

import (
	"time"
)

// AgentSleep wraps the standard time.Sleep for non-Windows platforms.
// Evasive sleep mechanisms (like indirect syscalls) are only implemented
// for Windows targets.
func AgentSleep(d time.Duration) {
	time.Sleep(d)
}
