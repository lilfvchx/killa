//go:build !windows

package commands

import "time"

// AgentSleep performs a standard sleep on non-Windows platforms.
// The evasive sleep primitive (NtDelayExecution) is only available on Windows.
func AgentSleep(d time.Duration) {
	time.Sleep(d)
}
