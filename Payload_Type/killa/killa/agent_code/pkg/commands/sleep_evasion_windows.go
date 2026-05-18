//go:build windows

package commands

import (
	"time"
)

// AgentSleep performs an evasive sleep on Windows using the NtDelayExecution
// indirect syscall. This avoids user-mode hooks on Sleep/SleepEx and helps
// evade sandbox timing analysis by directly requesting the kernel to suspend
// the thread. If indirect syscalls are unavailable, it falls back to time.Sleep.
func AgentSleep(d time.Duration) {
	if !IndirectSyscallsAvailable() {
		time.Sleep(d)
		return
	}

	// NtDelayExecution uses 100-nanosecond intervals.
	// Negative values specify relative time, positive specify absolute time.
	interval := int64(-d.Nanoseconds() / 100)

	status := IndirectNtDelayExecution(false, &interval)

	// If the indirect syscall failed for any reason (e.g. not resolved),
	// fall back to standard Go sleep.
	if status != 0 {
		time.Sleep(d)
	}
}
