# Iteration 2026-04-17: Evasive Sleep Primitive

## Context
The agent currently relies on the standard Go `time.Sleep` function to introduce delays between beacon cycles and during polling. This reliance translates to standard `Sleep` or `WaitForSingleObject` API calls in the Windows environment, which are easily hooked and monitored by EDR solutions. This monitoring can reveal the agent's behavior pattern, such as the exact frequency and duration of beaconing, allowing for fingerprinting and detection.

## Technique / Primitive
To mitigate this detection vector, we will implement an evasive sleep primitive leveraging the existing indirect syscall mechanism on Windows. We will utilize the `NtDelayExecution` native API call indirectly.

By resolving the syscall number for `NtDelayExecution` directly from `ntdll.dll` and executing it via an indirect stub (syscall;ret), we bypass user-mode hooks placed on high-level sleep functions like `kernel32!Sleep`.

## Reasoning
This approach significantly improves the stealth and resilience of the agent's core beaconing loop. It reduces the agent's footprint by avoiding standard, heavily monitored API calls for routine delays, complicating behavioral analysis and making the execution profile indistinguishable from more advanced, legitimate software or custom system utilities.

## Code Changes
1. **`indirect_syscalls_windows.go`:**
   - Add `"NtDelayExecution"` to the `keyFunctions` slice for syscall resolution.
   - Implement the `IndirectNtDelayExecution` wrapper function to execute the syscall with the resolved stub.
2. **`sleep_evasion_windows.go` (new):**
   - Implement `commands.AgentSleep(d time.Duration)` for the `windows` build tag. This function will translate the Go `time.Duration` into the required relative negative 100-nanosecond interval format for `NtDelayExecution` and call `IndirectNtDelayExecution`.
3. **`sleep_evasion_other.go` (new):**
   - Implement `commands.AgentSleep(d time.Duration)` for non-Windows platforms, falling back to standard `time.Sleep`.
4. **`main.go` & `slack.go`:**
   - Replace invocations of `time.Sleep` with `commands.AgentSleep` in the main beaconing loop and polling mechanisms where significant, predictable delays occur.

## Validation
Success will be validated through:
- Successful cross-compilation for both Windows and Linux architectures.
- Verification that the agent successfully sleeps and wakes up according to the configured interval and jitter during execution.
- Review of the resulting binary to ensure indirect syscall mechanisms are invoked instead of standard sleep APIs.