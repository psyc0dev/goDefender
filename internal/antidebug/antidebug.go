package antidebug

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/psyc0dev/goDefender/internal/models"
	"github.com/psyc0dev/goDefender/internal/utils"
	"golang.org/x/sys/windows"
)

type Debugger struct {
	Winapi               *utils.WinAPI
	blacklistedProcesses []string
	blacklistedProcMap   map[string]struct{}
	blacklistedWindows   []string
}

type ProcessInfo struct {
	Res1             uintptr
	PebAddr          uintptr
	Res2             [2]uintptr
	PID              uintptr
	InheritedFromPID uintptr
}

func New() *Debugger {
	procs := []string{
		// Debuggers & Disassemblers
		"x64dbg.exe", "x32dbg.exe", "x96dbg.exe", "ollydbg.exe", "windbg.exe", "windbgx.exe",
		"ida.exe", "ida64.exe", "idag.exe", "idag64.exe", "idaw.exe", "idaw64.exe", "idaq.exe", "idaq64.exe", "idat.exe", "idat64.exe",
		"ghidra.exe", "radare2.exe", "cutter.exe", "binaryninja.exe", "immunitydebugger.exe", "windasm.exe", "gdb.exe",
		// .NET / Bytecode Decompilers
		"dnspy.exe", "dnspy.console.exe", "ilspy.exe", "de4dot.exe", "dotpeek.exe", "reflexil.exe",
		// System & Process Monitoring
		"processhacker.exe", "systeminformer.exe", "procexp.exe", "procexp64.exe", "procmon.exe", "procmon64.exe",
		"autoruns.exe", "autorunsc.exe", "taskmgr.exe", "process.exe", "ksdumper.exe", "ksdumperclient.exe",
		"apimonitor.exe", "apimonitor-x64.exe", "apimonitor-x86.exe", "scylla.exe", "scylla_x64.exe", "scylla_x86.exe",
		// Network Sniffing & Traffic Interception
		"wireshark.exe", "fiddler.exe", "fiddlerclassic.exe", "fiddlereverywhere.exe", "charles.exe", "burpsuite.exe",
		"httpdebuggerui.exe", "httpanalyzerv7.exe", "tcpview.exe", "tcpview64.exe", "rawshark.exe", "tshark.exe",
		// Memory / PE Analysis & Reverse Engineering
		"pestudio.exe", "pe-bear.exe", "die.exe", "hxd.exe", "cheatengine-x86_64.exe", "cheatengine-i386.exe",
		"cheatengine-x86_64-sse4-avx2.exe", "resourcehacker.exe", "regedit.exe", "vboxservice.exe", "decoder.exe",
	}

	procMap := make(map[string]struct{}, len(procs))
	for _, p := range procs {
		procMap[strings.ToLower(p)] = struct{}{}
	}

	return &Debugger{
		Winapi:               utils.NewWinAPI(),
		blacklistedProcesses: procs,
		blacklistedProcMap:   procMap,
		blacklistedWindows: []string{
			"x64dbg", "x32dbg", "x96dbg", "ollydbg", "windbg", "ida pro", "ida v", "ida -",
			"ghidra", "cutter", "radare2", "binary ninja", "immunitydebugger", "debugger",
			"dnspy", "ilspy", "de4dot", "dotpeek", "reflexil", "codecracker", "simpleassembly",
			"process hacker", "system informer", "process explorer", "process monitor", "extremedumper",
			"ksdumper", "cheat engine", "scylla", "titanhide", "titanHide", "strongod",
			"wireshark", "fiddler", "charles", "burp suite", "http debugger", "httpdebugger", "tcpview",
			"api monitor", "pestudio", "pe-bear", "detect it easy", "hxd", "resource hacker",
			"proxifier", "graywolf", "exeinfope", "zed", "pc-ret", "de4dotmodded", "stringdecryptor",
		},
	}
}

func (d *Debugger) IsDebuggerPresent() bool {
	return d.Winapi.IsDebuggerPresent()
}

func (d *Debugger) PatchAntiDebug() bool {
	ntdllModule := d.Winapi.GetModuleHandle("ntdll.dll")
	if ntdllModule == 0 {
		return false
	}

	dbgUiRemoteBreakinAddr := d.Winapi.GetProcAddress(ntdllModule, "DbgUiRemoteBreakin")
	dbgBreakPointAddr := d.Winapi.GetProcAddress(ntdllModule, "DbgBreakPoint")

	if dbgUiRemoteBreakinAddr == 0 || dbgBreakPointAddr == 0 {
		return false
	}

	int3InvalidCode := []byte{0xCC}
	retCode := []byte{0xC3}

	status1 := d.Winapi.WriteProcessMemory(dbgUiRemoteBreakinAddr, int3InvalidCode)
	status2 := d.Winapi.WriteProcessMemory(dbgBreakPointAddr, retCode)

	return status1 && status2
}

func (d *Debugger) SetDebugFilterState() bool {
	return d.Winapi.SetDebugFilterState(0, 0, true)
}

func (d *Debugger) CheckRemoteDebugger() (bool, error) {
	return d.Winapi.CheckRemoteDebugger()
}

func (d *Debugger) GetRunningProcessCount() (int, error) {
	return d.Winapi.GetRunningProcessCount()
}

func (d *Debugger) CheckInternetConnection() (bool, error) {
	conn, err := net.Dial("tcp", "google.com:80")
	if err != nil {
		return false, err
	}
	defer conn.Close()
	return true, nil
}

func (d *Debugger) CheckBlacklistedProcesses() (bool, string, error) {
	processNames, err := d.Winapi.GetRunningProcessNames()
	if err != nil {
		return false, "", err
	}

	for _, processName := range processNames {
		processNameLower := strings.ToLower(processName)
		if _, exists := d.blacklistedProcMap[processNameLower]; exists {
			return true, processName, nil
		}
	}

	return false, "", nil
}

func (d *Debugger) CheckRepetitiveProcesses(threshold int) (bool, error) {
	processNames, err := d.Winapi.GetRunningProcessNames()
	if err != nil {
		return false, err
	}

	processCounts := make(map[string]int)
	for _, processName := range processNames {
		processName = strings.ToLower(processName)
		if processName != "svchost.exe" {
			processCounts[processName]++
		}
	}

	for _, count := range processCounts {
		if count > threshold {
			return true, nil
		}
	}

	return false, nil
}

func (d *Debugger) CheckParentProcess() (bool, string) {
	const ProcInfo = 0
	var p ProcessInfo

	handle := syscall.Handle(windows.CurrentProcess())

	r1, _, err := d.Winapi.QueryInformationProcess(
		handle,
		ProcInfo,
		uintptr(unsafe.Pointer(&p)),
		uint32(unsafe.Sizeof(p)),
	)

	if r1 != 0 || (err != nil && err != syscall.Errno(0)) {
		return false, "Failed to query process information"
	}

	parentPID := int32(p.InheritedFromPID)
	if parentPID == 0 {
		return false, "Invalid parent PID 0"
	}

	parentHandle, err := syscall.OpenProcess(syscall.PROCESS_QUERY_INFORMATION, false, uint32(parentPID))
	if err != nil {
		return false, fmt.Sprintf("Failed to open parent PID %d", parentPID)
	}
	defer syscall.CloseHandle(parentHandle)

	var nameBuffer [windows.MAX_PATH]uint16
	size := uint32(len(nameBuffer))
	err = windows.QueryFullProcessImageName(windows.Handle(parentHandle), 0, &nameBuffer[0], &size)
	if err != nil {
		return false, "Failed to query parent image name"
	}

	parentName := strings.ToLower(filepath.Base(syscall.UTF16ToString(nameBuffer[:size])))
	validParents := []string{
		"explorer.exe", "cmd.exe", "powershell.exe", "pwsh.exe",
		"windowsterminal.exe", "code.exe", "devenv.exe", "services.exe",
	}

	for _, valid := range validParents {
		if parentName == valid {
			return true, parentName
		}
	}

	return false, parentName
}

func (d *Debugger) CheckBlacklistedWindows() (bool, string) {
	user32 := windows.NewLazySystemDLL("user32.dll")
	procGetWindowText := user32.NewProc("GetWindowTextW")
	procEnumWindows := user32.NewProc("EnumWindows")

	var foundTitle string
	var enumWindowsProc = func(hwnd windows.HWND, lparam uintptr) uintptr {
		var title [256]uint16
		procGetWindowText.Call(
			uintptr(hwnd),
			uintptr(unsafe.Pointer(&title[0])),
			uintptr(len(title)),
		)
		windowTitle := syscall.UTF16ToString(title[:])

		for _, blacklisted := range d.blacklistedWindows {
			if strings.Contains(strings.ToLower(windowTitle), strings.ToLower(blacklisted)) {
				foundTitle = windowTitle
				return 0
			}
		}
		return 1
	}

	procEnumWindows.Call(
		windows.NewCallback(enumWindowsProc),
		0,
	)
	return foundTitle != "", foundTitle
}

// RunAllChecks performs comprehensive Anti-Debug diagnostics returning structured results.
func (d *Debugger) RunAllChecks() []models.CheckResult {
	var results []models.CheckResult

	// IsDebuggerPresent
	if d.IsDebuggerPresent() {
		results = append(results, models.CheckResult{
			Category: models.CategoryAntiDebug,
			Name:     "IsDebuggerPresent Flag",
			Detected: true,
			Severity: models.SeverityCritical,
			Details:  "PEB BeingDebugged flag is set",
		})
	} else {
		results = append(results, models.CheckResult{
			Category: models.CategoryAntiDebug,
			Name:     "IsDebuggerPresent Flag",
			Detected: false,
			Severity: models.SeverityInfo,
			Details:  "No direct debugger attached",
		})
	}

	// CheckRemoteDebugger
	if isRemote, err := d.CheckRemoteDebugger(); err != nil {
		results = append(results, models.CheckResult{Category: models.CategoryAntiDebug, Name: "CheckRemoteDebuggerPresent", Error: err})
	} else if isRemote {
		results = append(results, models.CheckResult{
			Category: models.CategoryAntiDebug,
			Name:     "CheckRemoteDebuggerPresent",
			Detected: true,
			Severity: models.SeverityCritical,
			Details:  "Remote debugger port detected on current process",
		})
	} else {
		results = append(results, models.CheckResult{
			Category: models.CategoryAntiDebug,
			Name:     "CheckRemoteDebuggerPresent",
			Detected: false,
			Severity: models.SeverityInfo,
			Details:  "No remote debugger detected",
		})
	}

	// Blacklisted Processes
	if badProc, procName, err := d.CheckBlacklistedProcesses(); err != nil {
		results = append(results, models.CheckResult{Category: models.CategoryAntiDebug, Name: "Analysis Processes", Error: err})
	} else if badProc {
		results = append(results, models.CheckResult{
			Category: models.CategoryAntiDebug,
			Name:     "Analysis Processes",
			Detected: true,
			Severity: models.SeverityHigh,
			Details:  fmt.Sprintf("Disallowed analysis tool running: %s", procName),
		})
	} else {
		results = append(results, models.CheckResult{
			Category: models.CategoryAntiDebug,
			Name:     "Analysis Processes",
			Detected: false,
			Severity: models.SeverityInfo,
			Details:  "No blacklisted analysis processes running",
		})
	}

	// Blacklisted Window Titles
	if foundWin, title := d.CheckBlacklistedWindows(); foundWin {
		results = append(results, models.CheckResult{
			Category: models.CategoryAntiDebug,
			Name:     "Analysis Windows",
			Detected: true,
			Severity: models.SeverityMedium,
			Details:  fmt.Sprintf("Disallowed tool window title active: %s", title),
		})
	} else {
		results = append(results, models.CheckResult{
			Category: models.CategoryAntiDebug,
			Name:     "Analysis Windows",
			Detected: false,
			Severity: models.SeverityInfo,
			Details:  "No suspicious debugger or decompiler windows open",
		})
	}

	// Parent Process
	if isValid, parent := d.CheckParentProcess(); !isValid {
		results = append(results, models.CheckResult{
			Category: models.CategoryAntiDebug,
			Name:     "Parent Process Verification",
			Detected: true,
			Severity: models.SeverityMedium,
			Details:  fmt.Sprintf("Unusual parent process: %s", parent),
		})
	} else {
		results = append(results, models.CheckResult{
			Category: models.CategoryAntiDebug,
			Name:     "Parent Process Verification",
			Detected: false,
			Severity: models.SeverityInfo,
			Details:  fmt.Sprintf("Legitimate parent process: %s", parent),
		})
	}

	return results
}
