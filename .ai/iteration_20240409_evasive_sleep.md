# Iteration: Evasive Sleep implementation
Date: 2024-04-09

## Technical Context
The agent previously relied on the standard Go `time.Sleep` implementation across all platforms. On Windows, this translates to standard, highly monitored API calls (e.g. `Sleep` or `NtDelayExecution` via direct userland jumps) that Endpoint Detection and Response (EDR) solutions and sandboxes routinely hook to detect or fast-forward execution (sandbox evasion bypass) and profile beaconing behavior.

## Technique / Primitive Implemented
To mitigate this visibility, we implemented an **Evasive Sleep** primitive specifically targeting Windows platforms by wrapping the `NtDelayExecution` syscall in our custom `IndirectSyscall` mechanism.

**Windows Internals References**:
- `NtDelayExecution`: A low-level NTAPI function used to suspend the execution of the current thread for a specified interval.
- **Indirect Syscalls (TartarusGate-like)**: By extracting the syscall number and jumping to a `syscall; ret` instruction already residing within the legitimate `ntdll.dll` memory space, we bypass user-mode hooks (API hooking) placed by security products on functions like `kernel32!Sleep` or `ntdll!NtDelayExecution`.

## Reasoning
This iteration aligns with the core pillar of **Sigilo Estructural y Minimización de Huella** (Structural Stealth and Footprint Minimization). By eliminating direct calls to standard sleep APIs on Windows, the agent's sleep behavior becomes significantly harder to detect and modify by userland hooks. It leverages the existing indirect syscall architecture, keeping the footprint minimal and the execution consistent, thus achieving better **Resiliencia Adaptativa** (Adaptive Resilience) against behavioral analysis.

## Code Changes
1. Added `"NtDelayExecution"` to the `keyFunctions` slice in `indirect_syscalls_windows.go`.
2. Created a strongly-typed wrapper `IndirectNtDelayExecution` that translates Go's duration to the required 100-nanosecond intervals and invokes the indirect syscall.
3. Created an abstraction `AgentSleep(d time.Duration)` in `agent_sleep_windows.go` that attempts to use the indirect syscall and falls back gracefully to `time.Sleep` if unavailable.
4. Created an `agent_sleep_other.go` to maintain cross-platform compatibility by defaulting to `time.Sleep` on non-Windows platforms.
5. Refactored the core agent loop (`main.go`) and various command execution routines (`pty`, `exec`, `spray`, `ptrace_inject`, `watch_dir`) to utilize this new primitive.

## Validation
1. **Compilation Check**: Ensure `GOOS=windows go build` completes without errors.
2. **Unit Testing**: Included `agent_sleep_test.go` to verify sleep functionality does not introduce logic errors or premature wakeups.
3. **Operational Metrics**: Expected behavior is that beaconing continues as normal on Windows, but the call stack for the sleep operation originates from an unhooked `ntdll.dll` stub, effectively bypassing user-land telemetry for timing functions.
