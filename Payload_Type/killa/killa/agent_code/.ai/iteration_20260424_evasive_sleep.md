# Iteration: Evasive Sleep via Indirect Syscalls

## Technical Context
The agent currently relies on the standard Go `time.Sleep` function for its beaconing delays and other sleep operations. This function maps directly to `Sleep` or `SleepEx` on Windows, which subsequently calls the `NtDelayExecution` syscall in `ntdll.dll`. Standard user-mode sleep functions are highly monitored by EDRs to profile beaconing patterns, analyze thread call stacks during sleep, and perform memory scanning.

## Technique Implemented
We are implementing a custom `AgentSleep` wrapper that replaces standard `time.Sleep` operations. On Windows, if indirect syscalls are initialized, this wrapper leverages a newly added `IndirectNtDelayExecution` stub to invoke the kernel sleep primitive directly. This avoids traversing the user-mode hooks typically placed on `kernel32.Sleep` or `ntdll.NtDelayExecution`.

The implementation passes a negative 100-nanosecond interval to `NtDelayExecution` to specify a relative delay, following the required Windows Internals format for this primitive:
`int64(-d.Nanoseconds() / 100)`

## Reasoning
This modification improves the structural stealth of the agent in several ways:
- **Hook Bypass:** Bypasses any inline hooks on `Sleep`, `SleepEx`, or `NtDelayExecution` in user-mode memory, ensuring the delay execution goes unnoticed by simplistic API monitoring.
- **Minimization of Footprint:** By standardizing sleep behavior through a single syscall primitive, we reduce the surface area and variations in our wait operations, contributing to a more resilient execution flow.

## Code Changes
1. **`indirect_syscalls_windows.go`:** Appended `"NtDelayExecution"` to the `keyFunctions` slice to resolve its stub during startup. Added the `IndirectNtDelayExecution` wrapper to execute the `syscall.SyscallN`.
2. **`agent_sleep_windows.go`:** Created to define `commands.AgentSleep`. It uses `IndirectNtDelayExecution` when `IndirectSyscallsAvailable()` is true, passing a correctly formatted relative delay pointer directly within the `SyscallN` arguments. Falls back to `time.Sleep` otherwise.
3. **`agent_sleep_other.go`:** Created as a no-op standard fallback (calling `time.Sleep`) for non-Windows architectures.
4. **`main.go`:** Refactored all direct usages of `time.Sleep` that manage beaconing delays to use `commands.AgentSleep`.

## Validation
Success will be validated by successfully compiling the agent on Windows and Linux (`GOOS=windows go build ./...` and `GOOS=linux go build ./...`). Targeted unit tests for the sleep functionality (e.g., `TestGuardedSleep`) will be executed with a local Go toolchain to ensure the timing logic operates exactly as expected with the new implementation.
