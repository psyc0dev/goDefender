package hooks

import (
	"fmt"
	"strings"
	"unsafe"

	"github.com/psyc0dev/goDefender/internal/models"
	"github.com/psyc0dev/goDefender/internal/utils"
)

// InspectPrologueBytes evaluates machine code bytes against common hooking trampolines (detours, MinHook, FrHook, etc.)
func InspectPrologueBytes(bytes []byte) (bool, string) {
	if len(bytes) < 2 {
		return false, ""
	}

	b0 := bytes[0]
	b1 := bytes[1]

	// 0xCC: Software breakpoint / debug trap
	if b0 == 0xCC {
		return true, "INT3 breakpoint detected at entry"
	}
	// 0x90: NOP sled at start of function
	if b0 == 0x90 && b1 == 0x90 {
		return true, "NOP sled detected at entry"
	}
	// 0xE9: JMP rel32 (standard 5-byte near jump detour)
	if b0 == 0xE9 {
		return true, "JMP rel32 (near jump) hook detected"
	}
	// 0xEB: JMP rel8 (short jump detour)
	if b0 == 0xEB {
		return true, "JMP rel8 (short jump) hook detected"
	}
	// 0xFF 0x25: JMP [RIP+disp32] (x64 indirect trampoline)
	if b0 == 0xFF && b1 == 0x25 {
		return true, "JMP QWORD PTR [RIP+disp32] 64-bit indirect hook detected"
	}
	// 0x48 0xB8 ... 0xFF 0xE0: mov rax, imm64; jmp rax (x64 absolute jump hook)
	// or 0x48 0xB8 ... 0x50 0xC3: mov rax, imm64; push rax; ret
	if b0 == 0x48 && b1 == 0xB8 && len(bytes) >= 12 {
		if (bytes[10] == 0xFF && bytes[11] == 0xE0) || (bytes[10] == 0x50 && bytes[11] == 0xC3) {
			return true, "MOV RAX, imm64 detour hook detected"
		}
	}
	// 0x49 0xBA ... 0x41 0xFF 0xE2: mov r10, imm64; jmp r10
	if b0 == 0x49 && b1 == 0xBA && len(bytes) >= 13 && bytes[10] == 0x41 && bytes[11] == 0xFF && bytes[12] == 0xE2 {
		return true, "MOV R10, imm64 detour hook detected"
	}
	// 0x68 ... 0xC3: PUSH imm32; RET (push-return hook, 6 bytes: 0x68 [4 bytes imm] 0xC3)
	if b0 == 0x68 && len(bytes) >= 6 && bytes[5] == 0xC3 {
		return true, "PUSH-RET detour hook detected"
	}

	return false, ""
}

func inspectPrologue(funcAddr uintptr) (bool, string) {
	if funcAddr == 0 {
		return false, ""
	}
	bytes := unsafe.Slice((*byte)(unsafe.Pointer(funcAddr)), 16)
	return InspectPrologueBytes(bytes)
}

func isHooked(funcAddr uintptr) bool {
	hooked, _ := inspectPrologue(funcAddr)
	return hooked
}

type HookDetector struct {
	api *utils.WinAPI
}

func New() *HookDetector {
	return &HookDetector{
		api: utils.NewWinAPI(),
	}
}

// FindHookedFunctions checks critical system APIs across system DLLs and returns any hooked functions.
func (h *HookDetector) FindHookedFunctions() []string {
	libraries := []string{"kernel32.dll", "kernelbase.dll", "ntdll.dll", "user32.dll", "win32u.dll"}
	kernellibfunc := []string{"IsDebuggerPresent", "CheckRemoteDebuggerPresent", "GetThreadContext", "OutputDebugStringA", "GetTickCount"}
	ntdllfunc := []string{"NtQueryInformationProcess", "NtSetInformationThread", "NtGetContextThread", "NtYieldExecution"}
	user32func := []string{"FindWindowW", "FindWindowA", "GetForegroundWindow"}
	win32ufunc := []string{"NtUserFindWindowEx", "NtUserGetForegroundWindow"}

	var hooked []string
	for _, library := range libraries {
		hModule := h.api.LowLevelGetModuleHandle(library)
		if hModule == 0 {
			continue
		}

		var targetFuncs []string
		switch library {
		case "kernel32.dll", "kernelbase.dll":
			targetFuncs = kernellibfunc
		case "ntdll.dll":
			targetFuncs = ntdllfunc
		case "user32.dll":
			targetFuncs = user32func
		case "win32u.dll":
			targetFuncs = win32ufunc
		}

		for _, funcName := range targetFuncs {
			funcAddr := h.api.LowLevelGetProcAddress(hModule, funcName)
			if isHook, reason := inspectPrologue(funcAddr); isHook {
				hooked = append(hooked, fmt.Sprintf("%s!%s (%s)", library, funcName, reason))
			}
		}
	}
	return hooked
}

func (h *HookDetector) CheckHookIntegrity() models.CheckResult {
	hooked := h.FindHookedFunctions()
	if len(hooked) > 0 {
		return models.CheckResult{
			Category: models.CategoryHooks,
			Name:     "WinAPI Function Hooks",
			Detected: true,
			Severity: models.SeverityHigh,
			Details:  fmt.Sprintf("Hooked APIs detected: %s", strings.Join(hooked, ", ")),
		}
	}
	return models.CheckResult{
		Category: models.CategoryHooks,
		Name:     "WinAPI Function Hooks",
		Detected: false,
		Severity: models.SeverityInfo,
		Details:  "No suspicious prologue hooks detected in critical system APIs",
	}
}

func (h *HookDetector) AntiAntiDebug() bool {
	return len(h.FindHookedFunctions()) > 0
}

func DetectHooksOnCommonWinAPIFunctions(moduleName string, functions []string) bool {
	detector := New()
	if moduleName == "" {
		return detector.AntiAntiDebug()
	}
	hModule := detector.api.LowLevelGetModuleHandle(moduleName)
	if hModule == 0 {
		return false
	}
	for _, f := range functions {
		addr := detector.api.LowLevelGetProcAddress(hModule, f)
		if isHooked(addr) {
			return true
		}
	}
	return false
}