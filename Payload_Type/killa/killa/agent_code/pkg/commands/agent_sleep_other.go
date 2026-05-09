//go:build !windows

package commands

import (
	"time"
)

// AgentSleep executes a standard sleep on non-Windows platforms.
// The evasive NtDelayExecution indirect syscall is Windows-specific.
func AgentSleep(d time.Duration) {
	time.Sleep(d)
}
