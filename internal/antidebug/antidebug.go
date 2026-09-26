package antidebug

import (
	"fmt"
	"net"
	"os"
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
		"autoruns.exe", "autorunsc.exe", "ksdumper.exe", "ksdumperclient.exe",
		"apimonitor.exe", "apimonitor-x64.exe", "apimonitor-x86.exe", "scylla.exe", "scylla_x64.exe", "scylla_x86.exe",
		// Network Sniffing & Traffic Interception
		"wireshark.exe", "fiddler.exe", "fiddlerclassic.exe", "fiddlereverywhere.exe", "charles.exe", "burpsuite.exe",
		"httpdebuggerui.exe", "httpanalyzerv7.exe", "tcpview.exe", "tcpview64.exe", "rawshark.exe", "tshark.exe",
		// Memory / PE Analysis & Reverse Engineering
		"pestudio.exe", "pe-bear.exe", "die.exe", "hxd.exe", "cheatengine-x86_64.exe", "cheatengine-i386.exe",
		"cheatengine-x86_64-sse4-avx2.exe", "resourcehacker.exe",
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
			"ghidra", "cutter", "radare2", "binary ninja", "immunitydebugger",
			"dnspy", "ilspy", "de4dot", "dotpeek", "reflexil", "codecracker", "simpleassembly",
			"process hacker", "system informer", "process explorer", "process monitor", "extremedumper",
			"ksdumper", "cheat engine", "scylla", "titanhide", "titanHide", "strongod",
			"wireshark", "fiddler", "charles", "burp suite", "http debugger", "httpdebugger", "tcpview",
			"api monitor", "pestudio", "pe-bear", "detect it easy", "hxd", "resource hacker",
			"proxifier", "graywolf", "exeinfope", "pc-ret", "de4dotmodded", "stringdecryptor",
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

func (d *Debugger) CheckRepetitiveProcesses(threshold int) (bool, string, error) {
	processNames, err := d.Winapi.GetRunningProcessNames()
	if err != nil {
		return false, "", err
	}

	ignored := map[string]struct{}{
		"svchost.exe":         {},
		"conhost.exe":         {},
		"runtimebroker.exe":   {},
		"chrome.exe":          {},
		"msedge.exe":          {},
		"firefox.exe":         {},
		"code.exe":            {},
		"windowsterminal.exe": {},
	}

	processCounts := make(map[string]int)
	for _, processName := range processNames {
		name := strings.ToLower(processName)
		if _, skip := ignored[name]; !skip {
			processCounts[name]++
		}
	}

	for name, count := range processCounts {
		if count > threshold {
			return true, fmt.Sprintf("Abnormal repetition: %d instances of %s", count, name), nil
		}
	}

	return false, "", nil
}

func (d *Debugger) CheckParentProcess() (bool, string, error) {
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return false, "", err
	}
	defer windows.CloseHandle(snapshot)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	myPID := uint32(os.Getpid())
	var parentPID uint32

	if err := windows.Process32First(snapshot, &entry); err != nil {
		return false, "", err
	}

	pidToName := make(map[uint32]string)
	for {
		name := windows.UTF16ToString(entry.ExeFile[:])
		pidToName[entry.ProcessID] = name
		if entry.ProcessID == myPID {
			parentPID = entry.ParentProcessID
		}
		if err := windows.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}

	if parentPID == 0 {
		return false, "No parent process (orphaned or system)", nil
	}

	parentName, exists := pidToName[parentPID]
	if !exists {
		return false, "Parent process terminated", nil
	}

	parentLower := strings.ToLower(parentName)
	if _, isBlacklisted := d.blacklistedProcMap[parentLower]; isBlacklisted {
		return true, fmt.Sprintf("Spawned by blacklisted analysis tool: %s (PID: %d)", parentName, parentPID), nil
	}

	return false, parentName, nil
}

func (d *Debugger) CheckHardwareBreakpoints() (bool, error) {
	hThread, _, _ := d.Winapi.ProcGetCurrentThread.Call()
	if hThread == 0 {
		return false, nil
	}

	buf := make([]byte, 2048)
	addr := uintptr(unsafe.Pointer(&buf[0]))
	offset := (16 - (addr % 16)) % 16
	alignedPtr := addr + offset

	is64Bit := unsafe.Sizeof(uintptr(0)) == 8
	var flags uint32 = 0x00010010
	if is64Bit {
		flags = 0x00100010
		*(*uint32)(unsafe.Pointer(alignedPtr + 48)) = flags
	} else {
		*(*uint32)(unsafe.Pointer(alignedPtr)) = flags
	}

	ret, _, err := d.Winapi.ProcGetThreadContext.Call(hThread, alignedPtr)
	if ret == 0 {
		return false, err
	}

	if is64Bit {
		dr0 := *(*uint64)(unsafe.Pointer(alignedPtr + 72))
		dr1 := *(*uint64)(unsafe.Pointer(alignedPtr + 80))
		dr2 := *(*uint64)(unsafe.Pointer(alignedPtr + 88))
		dr3 := *(*uint64)(unsafe.Pointer(alignedPtr + 96))
		return dr0 != 0 || dr1 != 0 || dr2 != 0 || dr3 != 0, nil
	}

	dr0 := *(*uint32)(unsafe.Pointer(alignedPtr + 4))
	dr1 := *(*uint32)(unsafe.Pointer(alignedPtr + 8))
	dr2 := *(*uint32)(unsafe.Pointer(alignedPtr + 12))
	dr3 := *(*uint32)(unsafe.Pointer(alignedPtr + 16))
	return dr0 != 0 || dr1 != 0 || dr2 != 0 || dr3 != 0, nil
}

func (d *Debugger) CheckNtQueryProcessDebugPort() (bool, error) {
	var port uintptr
	currentProc, _, _ := d.Winapi.ProcGetCurrentProcess.Call()
	ret, _, err := d.Winapi.ProcNtQueryInformationProcess.Call(
		currentProc,
		7, // ProcessDebugPort
		uintptr(unsafe.Pointer(&port)),
		uintptr(unsafe.Sizeof(port)),
		0,
	)
	if ret != 0 {
		return false, err
	}
	return port != 0, nil
}

func (d *Debugger) CheckNtQueryProcessDebugFlags() (bool, error) {
	var debugFlags uint32
	currentProc, _, _ := d.Winapi.ProcGetCurrentProcess.Call()
	ret, _, err := d.Winapi.ProcNtQueryInformationProcess.Call(
		currentProc,
		0x1F, // ProcessDebugFlags
		uintptr(unsafe.Pointer(&debugFlags)),
		uintptr(unsafe.Sizeof(debugFlags)),
		0,
	)
	if ret != 0 {
		return false, err
	}
	return debugFlags == 0, nil
}

func (d *Debugger) CheckNtQueryProcessDebugObject() (bool, error) {
	var hDebugObject uintptr
	currentProc, _, _ := d.Winapi.ProcGetCurrentProcess.Call()
	ret, _, _ := d.Winapi.ProcNtQueryInformationProcess.Call(
		currentProc,
		0x1E, // ProcessDebugObjectHandle
		uintptr(unsafe.Pointer(&hDebugObject)),
		uintptr(unsafe.Sizeof(hDebugObject)),
		0,
	)
	return ret == 0 && hDebugObject != 0, nil
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

	// Parent Process Validation
	if isBadParent, parentDetails, err := d.CheckParentProcess(); err != nil {
		results = append(results, models.CheckResult{Category: models.CategoryAntiDebug, Name: "Parent Process Validation", Error: err})
	} else if isBadParent {
		results = append(results, models.CheckResult{
			Category: models.CategoryAntiDebug,
			Name:     "Parent Process Validation",
			Detected: true,
			Severity: models.SeverityCritical,
			Details:  parentDetails,
		})
	} else {
		results = append(results, models.CheckResult{
			Category: models.CategoryAntiDebug,
			Name:     "Parent Process Validation",
			Detected: false,
			Severity: models.SeverityInfo,
			Details:  fmt.Sprintf("Legitimate parent process: %s", parentDetails),
		})
	}

	// Repetitive Processes
	if hasRepetitive, repDetails, err := d.CheckRepetitiveProcesses(20); err == nil && hasRepetitive {
		results = append(results, models.CheckResult{
			Category: models.CategoryAntiDebug,
			Name:     "Repetitive Processes",
			Detected: true,
			Severity: models.SeverityLow,
			Details:  repDetails,
		})
	}

	// NtQueryInformationProcess ProcessDebugPort
	if isPortSet, err := d.CheckNtQueryProcessDebugPort(); err != nil {
		results = append(results, models.CheckResult{Category: models.CategoryAntiDebug, Name: "Kernel DebugPort", Error: err})
	} else if isPortSet {
		results = append(results, models.CheckResult{
			Category: models.CategoryAntiDebug,
			Name:     "Kernel DebugPort",
			Detected: true,
			Severity: models.SeverityCritical,
			Details:  "Active kernel debug port detected via NtQueryInformationProcess(ProcessDebugPort)",
		})
	} else {
		results = append(results, models.CheckResult{
			Category: models.CategoryAntiDebug,
			Name:     "Kernel DebugPort",
			Detected: false,
			Severity: models.SeverityInfo,
			Details:  "No kernel debug port attached",
		})
	}

	// NtQueryInformationProcess ProcessDebugFlags
	if debugInheritZero, err := d.CheckNtQueryProcessDebugFlags(); err == nil && debugInheritZero {
		results = append(results, models.CheckResult{
			Category: models.CategoryAntiDebug,
			Name:     "Kernel DebugFlags",
			Detected: true,
			Severity: models.SeverityCritical,
			Details:  "ProcessDebugFlags returned 0 (NoDebugInherit cleared by debugger)",
		})
	}

	// NtQueryInformationProcess ProcessDebugObjectHandle
	if hasDebugObj, err := d.CheckNtQueryProcessDebugObject(); err == nil && hasDebugObj {
		results = append(results, models.CheckResult{
			Category: models.CategoryAntiDebug,
			Name:     "Kernel DebugObject",
			Detected: true,
			Severity: models.SeverityCritical,
			Details:  "Active kernel debug object handle exists for current process",
		})
	}

	// Hardware Breakpoints (DR0-DR3)
	if hwBp, err := d.CheckHardwareBreakpoints(); err != nil {
		results = append(results, models.CheckResult{Category: models.CategoryAntiDebug, Name: "Hardware Breakpoints", Error: err})
	} else if hwBp {
		results = append(results, models.CheckResult{
			Category: models.CategoryAntiDebug,
			Name:     "Hardware Breakpoints",
			Detected: true,
			Severity: models.SeverityCritical,
			Details:  "CPU debug registers DR0-DR3 contain active hardware breakpoint addresses",
		})
	} else {
		results = append(results, models.CheckResult{
			Category: models.CategoryAntiDebug,
			Name:     "Hardware Breakpoints",
			Detected: false,
			Severity: models.SeverityInfo,
			Details:  "DR0-DR3 debug registers clear",
		})
	}

	return results
}
