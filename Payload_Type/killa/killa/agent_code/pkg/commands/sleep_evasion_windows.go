//go:build windows

package commands

import (
	"time"
)

// AgentSleep executes an evasive sleep using indirect syscalls on Windows.
// It bypasses standard Kernel32/KernelBase Sleep hooks by going directly to NtDelayExecution.
func AgentSleep(d time.Duration) {
	if !IndirectSyscallsAvailable() {
		time.Sleep(d)
		return
	}

	// NTSTATUS NtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);
	// DelayInterval is in 100-nanosecond intervals. A negative value specifies relative time.
	interval := -int64(d / (time.Nanosecond * 100))

	if status := IndirectNtDelayExecution(0, &interval); status != 0 {
		time.Sleep(d)
	}
}
