//go:build !windows

package commands

import "time"

// AgentSleep sleeps for the specified duration.
// On non-Windows platforms, it falls back to the standard time.Sleep.
func AgentSleep(d time.Duration) {
	time.Sleep(d)
}
