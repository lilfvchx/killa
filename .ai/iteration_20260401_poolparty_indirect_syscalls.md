# Iteration 20260401: PoolParty Indirect Syscalls Integration

## Context
The "PoolParty" process injection techniques (implemented in `poolpartyinjection.go`) currently rely on standard Windows API functions (e.g., `NtQueryInformationWorkerFactory`, `NtSetInformationWorkerFactory`, `NtSetTimer2`, `ZwSetInformationFile`, `ZwAssociateWaitCompletionPacket`, `ZwSetIoCompletion`, `NtAlpcCreatePort`, `NtAlpcSetInformation`, `NtAlpcConnectPort`) loaded lazily from `ntdll.dll` using `windows.NewLazySystemDLL` and `NewProc`. Calling these functions directly from user mode makes the agent highly susceptible to detection by Endpoint Detection and Response (EDR) solutions that place user-mode hooks on `ntdll.dll` exports.

## Technique / Primitive
This iteration refactors the PoolParty injection routines to leverage the agent's existing "indirect syscall" mechanism (`indirect_syscalls_windows.go`). By resolving syscall numbers dynamically (using Hell's/Halo's Gate) and constructing raw syscall stubs in dynamically allocated RWX memory, the agent bypasses standard API calls entirely. This ensures that the execution flow jumps directly into the kernel using the correct syscall number, evading inline user-mode hooks placed by security products.

## Reasoning
Enhancing PoolParty with indirect syscalls aligns with the goals of "Sigilo Estructural y Minimización de Huella" (Structural Stealth and Footprint Minimization). The current implementation, while advanced in its use of Thread Pool structures, still triggers user-mode telemetry via standard API calls. Replacing these with indirect syscalls significantly reduces the probability of behavioral detection, ensuring the agent operates "out of the radar of monitoring."

## Changes to Codebase
1. **`indirect_syscalls_windows.go`:**
   - Add new `Nt*` functions to the `keyFunctions` list in `InitIndirectSyscalls` to generate stubs for them:
     - `NtQueryInformationWorkerFactory`
     - `NtSetInformationWorkerFactory`
     - `NtSetTimer2`
     - `ZwSetInformationFile`
     - `ZwAssociateWaitCompletionPacket`
     - `ZwSetIoCompletion`
     - `NtAlpcCreatePort`
     - `NtAlpcSetInformation`
     - `NtAlpcConnectPort`
   - Implement wrapper functions (e.g., `IndirectNtQueryInformationWorkerFactory`, `IndirectNtSetInformationWorkerFactory`, etc.) that execute the generated stubs via `syscall.SyscallN`.

2. **`poolpartyinjection.go`:**
   - Update `executeVariant1` through `executeVariant8` to conditionally use the new `IndirectNt*` wrappers if `IndirectSyscallsAvailable()` returns true. Fall back to the existing `proc*.Call()` methodology if indirect syscalls are unavailable or fail to initialize.

## Validation
- Verify compilation on Windows (`GOOS=windows go build`).
- Ensure no regressions occur in the agent's core functionality.
- Since direct unit tests for PoolParty injection are not present, validation relies on verifying that the syntax is correct and the code successfully compiles, confirming the indirect syscall wrappers are correctly typed and integrated.