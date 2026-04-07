# Iteration: Enhance Indirect Syscalls with TartarusGate

## Technical Context
The `killa` agent utilizes indirect syscalls by parsing `ntdll.dll` to find syscall numbers and generate stubs that execute syscalls from within `ntdll` itself. However, the current implementation might fail to resolve syscall numbers if the `Nt*` function in `ntdll` is hooked by an EDR (Endpoint Detection and Response) solution. The current code has a basic HalosGate-like logic but lacks robustness and fallback mechanisms like TartarusGate for handling different EDR hook patterns.

## Concept / Technique
Implement a more robust HalosGate/TartarusGate mechanism to resolve syscall numbers dynamically even when standard API hooking techniques are heavily employed by security products. This involves checking adjacent syscalls (up and down) and calculating the correct syscall number based on the offsets, handling both standard jumps (like `jmp`) and other hook patterns (like `int 3` or `mov eax, sysnum`). We will also expand the set of key functions for better evasion coverage during process injection and token manipulation.

## Reasoning
Enhancing the indirect syscall resolver significantly improves the agent's resilience against modern EDR solutions that hook `ntdll.dll`. By reliably resolving syscall numbers even in heavily monitored environments, we minimize the architectural footprint and ensure stealthy execution of critical primitives like memory allocation and process manipulation.

## Changes
1.  **Refactor `parseExports` and `halosGate` in `indirect_syscalls_windows.go`**:
    *   Improve the scanning logic to identify hooked functions more reliably.
    *   Enhance the neighbor checking logic (HalosGate/TartarusGate) to correctly calculate syscall numbers by analyzing the opcodes of adjacent, unhooked functions.
2.  **Add `IndirectNt*` wrappers for process creation and memory operations**:
    *   Add wrappers for `NtCreateUserProcess`, `NtMapViewOfSection`, `NtUnmapViewOfSection`, and `NtCreateSection` to support more advanced and stealthy injection techniques like Module Stomping or Phantom DLL Hollowing later on.
    *   Ensure all new wrappers are properly registered in `keyFunctions`.

## Validation
*   Verify that the agent compiles successfully on Windows (`GOOS=windows go build`).
*   Test that the indirect syscalls initialization succeeds and doesn't crash the agent.
*   (If possible in the environment) Test process injection commands (e.g., `vanilla-injection`) to ensure they still work correctly using the newly resolved syscalls.
