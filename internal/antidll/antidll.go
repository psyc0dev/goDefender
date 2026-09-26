package antidll

import (
	"unsafe"

	"github.com/psyc0dev/goDefender/internal/utils"
)

type DLLProtector struct {
	winapi *utils.WinAPI
}

type PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY struct {
	MicrosoftSignedOnly uint32
}

const (
	ProcessSignaturePolicyMitigation = 8
)

func New() *DLLProtector {
	return &DLLProtector{
		winapi: utils.NewWinAPI(),
	}
}

func (d *DLLProtector) PreventDLLInjection() error {
	var onlyMicrosoftBinaries PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY
	onlyMicrosoftBinaries.MicrosoftSignedOnly = 1

	kernelbase := d.winapi.GetModuleHandle("kernelbase.dll")
	if kernelbase == 0 {
		return d.winapi.LastError()
	}

	procSetProcessMitigationPolicy := d.winapi.GetProcAddress(kernelbase, "SetProcessMitigationPolicy")
	if procSetProcessMitigationPolicy == 0 {
		return d.winapi.LastError()
	}

	ret, _, err := d.winapi.CallProc(
		procSetProcessMitigationPolicy,
		uintptr(ProcessSignaturePolicyMitigation),
		uintptr(unsafe.Pointer(&onlyMicrosoftBinaries)),
		uintptr(unsafe.Sizeof(onlyMicrosoftBinaries)),
	)

	if ret == 0 {
		return err
	}

	return nil
}

func (d *DLLProtector) PatchAllLoadLibrary() error {
	kernelbase := d.winapi.GetModuleHandle("kernelbase.dll")
	ntdll := d.winapi.GetModuleHandle("ntdll.dll")

	if kernelbase == 0 {
		return d.winapi.LastError()
	}

	is64Bit := unsafe.Sizeof(uintptr(0)) == 8

	// On x64: caller cleans stack, return NULL (0) via XOR EAX, EAX; RET (31 C0 C3)
	// On x86: callee cleans stack (stdcall)
	var loadLibPatch []byte
	var loadLibExPatch []byte
	var ldrLoadDllPatch []byte

	if is64Bit {
		loadLibPatch = []byte{0x31, 0xC0, 0xC3}
		loadLibExPatch = []byte{0x31, 0xC0, 0xC3}
		// NTSTATUS STATUS_ACCESS_DENIED (0xC0000022)
		ldrLoadDllPatch = []byte{0xB8, 0x22, 0x00, 0x00, 0xC0, 0xC3}
	} else {
		// x86 stdcall: XOR EAX, EAX; RET 4 (1 parameter)
		loadLibPatch = []byte{0x31, 0xC0, 0xC2, 0x04, 0x00}
		// x86 stdcall: XOR EAX, EAX; RET 12 (3 parameters)
		loadLibExPatch = []byte{0x31, 0xC0, 0xC2, 0x0C, 0x00}
		// x86 stdcall: MOV EAX, 0xC0000022; RET 16 (4 parameters)
		ldrLoadDllPatch = []byte{0xB8, 0x22, 0x00, 0x00, 0xC0, 0xC2, 0x10, 0x00}
	}

	for _, funcName := range []string{"LoadLibraryA", "LoadLibraryW"} {
		if funcAddr := d.winapi.GetProcAddress(kernelbase, funcName); funcAddr != 0 {
			d.winapi.WriteProcessMemory(funcAddr, loadLibPatch)
		}
	}

	for _, funcName := range []string{"LoadLibraryExA", "LoadLibraryExW"} {
		if funcAddr := d.winapi.GetProcAddress(kernelbase, funcName); funcAddr != 0 {
			d.winapi.WriteProcessMemory(funcAddr, loadLibExPatch)
		}
	}

	if ntdll != 0 {
		if funcAddr := d.winapi.GetProcAddress(ntdll, "LdrLoadDll"); funcAddr != 0 {
			d.winapi.WriteProcessMemory(funcAddr, ldrLoadDllPatch)
		}
	}

	return nil
}