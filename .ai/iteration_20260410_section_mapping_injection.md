# Iteration: Section Mapping Injection

## Context
As part of our Red Team R&D objectives, we need to continuously refine our deployment and execution primitives to evade detection. Traditional remote process injection techniques rely heavily on `VirtualAllocEx` (or its indirect equivalent `NtAllocateVirtualMemory`) and `WriteProcessMemory`. These APIs are highly monitored by EDR solutions and memory scanners, as they explicitly mark memory for execution and trigger cross-process memory write telemetry.

## Technique
We implemented a Section Mapping injection primitive utilizing Windows Internals concepts (Sections and Views). Instead of allocating memory directly in the target process, we:
1. Create a section object using `NtCreateSection` (`SECTION_ALL_ACCESS`, `PAGE_EXECUTE_READWRITE`).
2. Map a view of that section into our own (local) process as `PAGE_READWRITE` using `NtMapViewOfSection`.
3. Copy our payload (shellcode/PE) into the locally mapped view.
4. Map another view of the same section into the target remote process with the desired final protection (e.g., `PAGE_EXECUTE_READ`) using `NtMapViewOfSection`.
5. Unmap the local view.

## Reasoning
This technique provides significant stealth advantages:
* **Bypasses `VirtualAllocEx` / `WriteProcessMemory`**: We never call these highly-monitored APIs.
* **Hides Allocation Intent**: Creating a section is a generic OS operation used extensively by the system (e.g., for sharing memory or loading DLLs). It masks our intent compared to allocating explicit `PAGE_EXECUTE_READWRITE` memory.
* **Evades Cross-Process Write Hooks**: The actual memory write happens locally. The remote process gets the data "magically" because it maps the same physical memory section. This bypasses heuristics looking for cross-process writes of executable code.
* **Integration**: Upgrades all existing injection commands (Thread Hijack, APC, PoolParty, etc.) since we refactored the central `injectAllocWriteProtect` helper.

## Changes
* Added constants `SECTION_ALL_ACCESS` and `SEC_COMMIT` to `Payload_Type/killa/killa/agent_code/pkg/commands/injection_helpers_windows.go`.
* Added `NtCreateSection`, `NtMapViewOfSection`, and `NtUnmapViewOfSection` to the `keyFunctions` slice in `indirect_syscalls_windows.go` to dynamically resolve them.
* Implemented `IndirectNtCreateSection`, `IndirectNtMapViewOfSection`, and `IndirectNtUnmapViewOfSection` indirect syscall wrappers.
* Created `injectMapSection` in `injection_helpers_windows.go` that implements the technique.
* Refactored `injectAllocWriteProtect` to preferentially use `injectMapSection` when indirect syscalls are available.

## Validation
* Code compiles correctly for `GOOS=windows`.
* Test suite passes without regressions.
* Future field testing will confirm bypass of EDR memory allocation telemetry.
