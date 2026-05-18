//go:build !windows

package commands

import (
	"time"
)

// AgentSleep performs a standard sleep on non-Windows platforms.
// On Windows, this utilizes an evasive indirect syscall (NtDelayExecution).
func AgentSleep(d time.Duration) {
	time.Sleep(d)
}
