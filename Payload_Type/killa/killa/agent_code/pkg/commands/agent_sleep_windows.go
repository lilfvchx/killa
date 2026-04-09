//go:build windows

package commands

import (
	"time"
)

// AgentSleep performs a sleep using indirect syscalls on Windows to evade hooks,
// falling back to standard time.Sleep if indirect syscalls are unavailable.
func AgentSleep(d time.Duration) {
	if !IndirectSyscallsAvailable() {
		time.Sleep(d)
		return
	}

	// NTSTATUS NtDelayExecution expects the delay interval in 100-nanosecond intervals.
	// Negative value indicates relative time.
	delayInterval := int64(-d / (100 * time.Nanosecond))

	status := IndirectNtDelayExecution(false, &delayInterval)
	if status != 0 {
		// Fallback if NtDelayExecution fails
		time.Sleep(d)
	}
}
