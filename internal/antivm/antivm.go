package antivm

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/psyc0dev/goDefender/internal/models"
	"github.com/psyc0dev/goDefender/internal/utils"
	"github.com/StackExchange/wmi"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

type VMDetector struct {
	winapi       *utils.WinAPI
	badFileNames []string
	badDirs      []string
	badDrivers   []string
	anyRunUUIDs  []string
}

func New() *VMDetector {
	return &VMDetector{
		winapi: utils.NewWinAPI(),
		badFileNames: []string{
			// VirtualBox Guest Additions & Drivers
			"VBoxMouse.sys", "VBoxGuest.sys", "VBoxSF.sys", "VBoxVideo.sys", "vboxogl.dll",
			"vboxdisp.dll", "vboxmrxnp.dll", "vboxtray.exe", "vboxcontrol.exe", "vboxservice.exe",
			// VMware Tools & Drivers
			"vmmouse.sys", "vmhgfs.sys", "vmscsi.sys", "vmci.sys", "vmusb.sys", "vmxnet.sys",
			"vmx_svga.sys", "vmxnet3.sys", "vmtoolsd.exe", "vmwaretray.exe", "vmwareuser.exe",
			"VGAuthService.exe", "vmacthlp.exe", "vmusbmouse.sys", "vmmvmt.sys", "vmnet.sys", "vmsrvc.sys",
			// QEMU / KVM / Red Hat VirtIO Drivers
			"qemu-ga.exe", "qemufw.sys", "viostor.sys", "vioscsi.sys", "viorng.sys", "viomem.sys",
			"viogpudo.sys", "vioser.sys", "netkvm.sys", "balloon.sys", "vioinput.sys", "viofs.sys",
			// Parallels Desktop Drivers
			"prl_sf.sys", "prl_tg.sys", "prl_eth.sys", "prl_fs.sys", "prl_sound.sys", "prl_mouf.sys",
			"prl_pv30.sys", "prl_vnic.sys", "prl_boot.sys", "prl_paravirt.sys", "prl_tools.exe",
			// Xen Hypervisor Drivers
			"xenevtchn.sys", "xennet.sys", "xenvbd.sys", "xeniface.sys", "xenbus.sys",
		},
		badDirs: []string{
			`C:\Program Files\VMware`,
			`C:\Program Files (x86)\VMware`,
			`C:\Program Files\VMware\VMware Tools`,
			`C:\Program Files\Oracle\VirtualBox Guest Additions`,
			`C:\Program Files (x86)\Oracle\VirtualBox Guest Additions`,
			`C:\Program Files\Qemu-ga`,
			`C:\Program Files (x86)\Qemu-ga`,
			`C:\Program Files\Parallels\Parallels Tools`,
			`C:\Program Files\XenServer\XenTools`,
		},
		badDrivers: []string{
			"balloon.sys", "netkvm.sys", "vioinput.sys", "viofs.sys", "vioser.sys",
			"qemu-ga.exe", "qemuwmi.sys", "prl_sf.sys", "prl_tg.sys", "prl_eth.sys",
			"vboxguest.sys", "vboxmouse.sys", "vboxsf.sys", "vboxvideo.sys",
			"vmmouse.sys", "vmhgfs.sys", "vmci.sys", "vmxnet.sys",
		},
		anyRunUUIDs: []string{
			"bb926e54-e3ca-40fd-ae90-2764341e7792",
			"90059c37-1320-41a4-b58d-2b75a9850d2f",
		},
	}
}

func (v *VMDetector) getSystem32Path() string {
	systemDir := os.Getenv("SYSTEMROOT")
	if systemDir == "" {
		systemDir = `C:\Windows`
	}
	return filepath.Join(systemDir, "System32")
}

// CheckSMBIOSFirmware queries SMBIOS ACPI raw firmware tables for hypervisor / virtualization vendor signatures.
func (v *VMDetector) CheckSMBIOSFirmware() (bool, string, error) {
	const RSMB uint32 = 0x52534D42 // 'RSMB' provider signature
	data, err := v.winapi.GetSystemFirmwareTable(RSMB, 0)
	if err != nil {
		return false, "", err
	}

	dataLower := bytes.ToLower(data)
	vmKeywords := []string{
		"vmware", "virtualbox", "vbox", "qemu", "bochs", "kvm",
		"innotek", "parallels", "xen", "bhyve", "red hat", "seabios",
	}

	for _, kw := range vmKeywords {
		if bytes.Contains(dataLower, []byte(kw)) {
			return true, fmt.Sprintf("SMBIOS table contains virtualization indicator: %s", kw), nil
		}
	}
	return false, "", nil
}

// CheckBIOSRegistry inspects Windows hardware system registry for virtualization vendor identifiers.
func (v *VMDetector) CheckBIOSRegistry() (bool, string) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, registry.QUERY_VALUE)
	if err != nil {
		return false, ""
	}
	defer key.Close()

	checks := []string{"SystemManufacturer", "SystemProductName", "BIOSVendor", "BaseBoardManufacturer"}
	vmKeywords := []string{"vmware", "virtualbox", "vbox", "qemu", "kvm", "innotek", "parallels", "xen", "hyper-v", "seabios"}

	for _, valueName := range checks {
		val, _, err := key.GetStringValue(valueName)
		if err != nil {
			continue
		}
		valLower := strings.ToLower(val)
		for _, kw := range vmKeywords {
			if strings.Contains(valLower, kw) {
				return true, fmt.Sprintf("BIOS registry %s contains VM signature: %s", valueName, val)
			}
		}
	}
	return false, ""
}

// CheckHardwareConstraints checks if available CPU cores or RAM indicate a constrained sandbox/analysis VM.
func (v *VMDetector) CheckHardwareConstraints() (bool, string) {
	cores := v.winapi.GetProcessorCount()
	ramMB, err := v.winapi.GetPhysicalMemoryMB()

	var reasons []string
	if cores < 2 {
		reasons = append(reasons, fmt.Sprintf("Abnormally low CPU cores (%d core)", cores))
	}
	if err == nil && ramMB > 0 && ramMB < 3072 {
		reasons = append(reasons, fmt.Sprintf("Abnormally low RAM (%d MB)", ramMB))
	}

	if len(reasons) > 0 {
		return true, strings.Join(reasons, "; ")
	}
	return false, ""
}

// CheckTimingVariance measures high-resolution execution time delta to detect virtualization VM-exit overhead or debugger stepping.
func (v *VMDetector) CheckTimingVariance() (bool, string, error) {
	start, err := v.winapi.QueryPerformanceCounter()
	if err != nil {
		return false, "", err
	}

	// Tight loop execution
	var dummy int
	for i := 0; i < 500000; i++ {
		dummy += (i * 3) ^ (i >> 2)
	}

	end, err := v.winapi.QueryPerformanceCounter()
	if err != nil {
		return false, "", err
	}

	freq, err := v.winapi.QueryPerformanceFrequency()
	if err != nil || freq == 0 {
		return false, "", err
	}

	elapsedMs := float64(end-start) * 1000.0 / float64(freq)
	if elapsedMs > 150.0 {
		return true, fmt.Sprintf("Execution timing anomaly: 500k iterations took %.2f ms (threshold: 150ms)", elapsedMs), nil
	}
	return false, "", nil
}

func (v *VMDetector) CheckDisplayRefreshRate() (bool, error) {
	refreshRate, err := v.winapi.GetDisplayRefreshRate()
	if err != nil {
		return false, err
	}
	return refreshRate < 29, nil
}

func (v *VMDetector) CheckVMware() (bool, error) {
	var videoControllers []struct{ Name string }
	err := wmi.Query("SELECT Name FROM Win32_VideoController", &videoControllers)
	if err != nil {
		return false, err
	}

	for _, controller := range videoControllers {
		if strings.Contains(strings.ToLower(controller.Name), "vmware") {
			return true, nil
		}
	}
	return false, nil
}

func (v *VMDetector) CheckVirtualBox() (bool, error) {
	var videoControllers []struct{ Name string }
	err := wmi.Query("SELECT Name FROM Win32_VideoController", &videoControllers)
	if err != nil {
		return false, err
	}

	for _, controller := range videoControllers {
		if strings.Contains(strings.ToLower(controller.Name), "virtualbox") {
			return true, nil
		}
	}
	return false, nil
}

func (v *VMDetector) CheckKVM() (bool, error) {
	sys32 := v.getSystem32Path()
	driversDir := filepath.Join(sys32, "drivers")
	for _, driver := range v.badDrivers[:5] {
		if _, err := os.Stat(filepath.Join(sys32, driver)); err == nil {
			return true, nil
		}
		if _, err := os.Stat(filepath.Join(driversDir, driver)); err == nil {
			return true, nil
		}
	}
	return false, nil
}

func (v *VMDetector) CheckQEMU() (bool, error) {
	sys32 := v.getSystem32Path()
	driversDir := filepath.Join(sys32, "drivers")
	for _, driver := range v.badDrivers[5:7] {
		if _, err := os.Stat(filepath.Join(sys32, driver)); err == nil {
			return true, nil
		}
		if _, err := os.Stat(filepath.Join(driversDir, driver)); err == nil {
			return true, nil
		}
	}
	return false, nil
}

func (v *VMDetector) CheckParallels() (bool, error) {
	sys32 := v.getSystem32Path()
	driversDir := filepath.Join(sys32, "drivers")
	for _, driver := range v.badDrivers[7:] {
		if _, err := os.Stat(filepath.Join(sys32, driver)); err == nil {
			return true, nil
		}
		if _, err := os.Stat(filepath.Join(driversDir, driver)); err == nil {
			return true, nil
		}
	}
	return false, nil
}

func (v *VMDetector) CheckVMFiles() bool {
	sys32 := v.getSystem32Path()
	driversDir := filepath.Join(sys32, "drivers")

	for _, badFile := range v.badFileNames {
		if _, err := os.Stat(filepath.Join(sys32, badFile)); err == nil {
			return true
		}
		if _, err := os.Stat(filepath.Join(driversDir, badFile)); err == nil {
			return true
		}
	}

	for _, badDir := range v.badDirs {
		if _, err := os.Stat(badDir); err == nil {
			return true
		}
	}
	return false
}

// CheckPortConnectors queries physical motherboard connectors.
func (v *VMDetector) CheckPortConnectors() (bool, error) {
	var portConnectors []struct{ Tag string }
	err := wmi.Query("SELECT * FROM Win32_PortConnector", &portConnectors)
	if err != nil {
		return false, err
	}
	return len(portConnectors) == 0, nil
}

func (v *VMDetector) CheckScreenSize() (bool, error) {
	getSystemMetrics := syscall.NewLazyDLL("user32.dll").NewProc("GetSystemMetrics")
	width, _, _ := getSystemMetrics.Call(0)
	height, _, _ := getSystemMetrics.Call(1)
	if width == 0 || height == 0 {
		return false, nil
	}
	return width < 800 || height < 600, nil
}

func (v *VMDetector) CheckAnyRun() bool {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer key.Close()

	machineGuid, _, err := key.GetStringValue("MachineGuid")
	if err != nil {
		return false
	}

	for _, uuid := range v.anyRunUUIDs {
		if uuid == machineGuid {
			return true
		}
	}
	return false
}

func (v *VMDetector) CheckUSBDevices() (bool, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Enum\USBSTOR`, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		// Key doesn't exist - no USB storage device has ever been connected
		return true, nil
	}
	defer key.Close()

	subKeys, err := key.ReadSubKeyNames(0)
	if err != nil {
		return false, err
	}
	return len(subKeys) == 0, nil
}

func (v *VMDetector) CheckBlacklistedUsernames() bool {
	blacklistedNames := []string{
		"johnson", "miller", "malware", "maltest", "currentuser", "sandbox",
		"virus", "john doe", "test user", "sand box", "wdagutilityaccount",
		"bruno", "george", "harry johnson", "vmware", "virtualbox", "vbox",
		"qemu", "cuckoo", "user", "admin", "sample", "analyzer", "test",
		"desktop", "victim", "pcap", "runner", "appveyor", "travis", "circleci",
	}

	username := strings.ToLower(os.Getenv("USERNAME"))
	for _, name := range blacklistedNames {
		if username == strings.ToLower(name) {
			return true
		}
	}
	return false
}

func (v *VMDetector) CheckSandboxie() bool {
	handle := v.winapi.GetModuleHandle("SbieDll.dll")
	return handle != 0
}

func (v *VMDetector) CheckComodoSandbox() bool {
	handle32 := v.winapi.GetModuleHandle("cmdvrt32.dll")
	handle64 := v.winapi.GetModuleHandle("cmdvrt64.dll")
	return handle32 != 0 || handle64 != 0
}

func (v *VMDetector) CheckQihoo360Sandbox() bool {
	handle := v.winapi.GetModuleHandle("SxIn.dll")
	return handle != 0
}

func (v *VMDetector) CheckCuckooSandbox() bool {
	handle := v.winapi.GetModuleHandle("cuckoomon.dll")
	return handle != 0
}

func (v *VMDetector) CheckWine() bool {
	moduleHandle := v.winapi.GetModuleHandle("kernel32.dll")
	if moduleHandle == 0 {
		return false
	}

	procAddr := v.winapi.GetProcAddress(moduleHandle, "wine_get_unix_file_name")
	return procAddr != 0
}

func (v *VMDetector) CheckNamedPipes() bool {
	suspiciousDevices := []string{
		`\\.\pipe\cuckoo`,
		`\\.\HGFS`,
		`\\.\vmci`,
		`\\.\VBoxMiniRdrDN`,
		`\\.\VBoxGuest`,
		`\\.\pipe\VBoxMiniRdDN`,
		`\\.\VBoxTrayIPC`,
		`\\.\pipe\VBoxTrayIPC`,
		`\\.\pipe\sandbox`,
		`\\.\pipe\vmware`,
		`\\.\pipe\vbox`,
		`\\.\pipe\qemu`,
		`\\.\pipe\analysis`,
		`\\.\pipe\debug`,
		`\\.\pipe\monitor`,
		`\\.\pipe\wireshark`,
		`\\.\pipe\frida`,
		`\\.\pipe\sandboxapi`,
		`\\.\pipe\windbg`,
	}

	for _, device := range suspiciousDevices {
		pathPtr, err := windows.UTF16PtrFromString(device)
		if err != nil {
			continue
		}
		handle, err := windows.CreateFile(
			pathPtr,
			0,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
			nil,
			windows.OPEN_EXISTING,
			0,
			0,
		)
		if handle != windows.InvalidHandle {
			windows.CloseHandle(handle)
			return true
		}
		if err == windows.ERROR_ACCESS_DENIED || err == windows.ERROR_PIPE_BUSY {
			return true
		}
	}
	return false
}

// RunAllChecks performs comprehensive Anti-VM and virtualization diagnostics returning structured results.
func (v *VMDetector) RunAllChecks() []models.CheckResult {
	var results []models.CheckResult

	// SMBIOS Firmware
	if isVM, details, err := v.CheckSMBIOSFirmware(); err != nil {
		results = append(results, models.CheckResult{Category: models.CategoryHardware, Name: "SMBIOS Firmware Table", Error: err})
	} else {
		results = append(results, models.CheckResult{Category: models.CategoryHardware, Name: "SMBIOS Firmware Table", Detected: isVM, Severity: models.SeverityCritical, Details: details})
	}

	// BIOS Registry
	if isVMBios, details := v.CheckBIOSRegistry(); isVMBios {
		results = append(results, models.CheckResult{Category: models.CategoryHardware, Name: "BIOS Registry Configuration", Detected: true, Severity: models.SeverityCritical, Details: details})
	} else {
		results = append(results, models.CheckResult{Category: models.CategoryHardware, Name: "BIOS Registry Configuration", Detected: false, Severity: models.SeverityInfo, Details: "Normal hardware manufacturer in BIOS registry"})
	}

	// Hardware Specs
	if isConstrained, details := v.CheckHardwareConstraints(); isConstrained {
		results = append(results, models.CheckResult{Category: models.CategoryHardware, Name: "Hardware Resources", Detected: true, Severity: models.SeverityMedium, Details: details})
	} else {
		results = append(results, models.CheckResult{Category: models.CategoryHardware, Name: "Hardware Resources", Detected: false, Severity: models.SeverityInfo, Details: "Normal CPU/RAM configuration"})
	}

	// Timing Variance
	if timingAnomaly, details, err := v.CheckTimingVariance(); err != nil {
		results = append(results, models.CheckResult{Category: models.CategoryTiming, Name: "Execution Timing Variance", Error: err})
	} else {
		results = append(results, models.CheckResult{Category: models.CategoryTiming, Name: "Execution Timing Variance", Detected: timingAnomaly, Severity: models.SeverityMedium, Details: details})
	}

	// Display Refresh Rate
	if lowRefresh, err := v.CheckDisplayRefreshRate(); err != nil {
		results = append(results, models.CheckResult{Category: models.CategoryAntiVM, Name: "Display Refresh Rate", Error: err})
	} else {
		results = append(results, models.CheckResult{Category: models.CategoryAntiVM, Name: "Display Refresh Rate", Detected: lowRefresh, Severity: models.SeverityLow, Details: "Refresh rate < 29Hz"})
	}

	// Screen Size
	if smallScreen, err := v.CheckScreenSize(); err != nil {
		results = append(results, models.CheckResult{Category: models.CategoryAntiVM, Name: "Screen Resolution", Error: err})
	} else {
		results = append(results, models.CheckResult{Category: models.CategoryAntiVM, Name: "Screen Resolution", Detected: smallScreen, Severity: models.SeverityLow, Details: "Screen size < 800x600"})
	}

	// VMware
	if isVMware, err := v.CheckVMware(); err == nil && isVMware {
		results = append(results, models.CheckResult{Category: models.CategoryAntiVM, Name: "VMware Video Controller", Detected: true, Severity: models.SeverityHigh, Details: "VMware graphics adapter identified"})
	}

	// VirtualBox
	if isVBox, err := v.CheckVirtualBox(); err == nil && isVBox {
		results = append(results, models.CheckResult{Category: models.CategoryAntiVM, Name: "VirtualBox Video Controller", Detected: true, Severity: models.SeverityHigh, Details: "VirtualBox graphics adapter identified"})
	}

	// KVM / QEMU / Parallels
	if isKVM, _ := v.CheckKVM(); isKVM {
		results = append(results, models.CheckResult{Category: models.CategoryAntiVM, Name: "KVM Hypervisor Drivers", Detected: true, Severity: models.SeverityHigh, Details: "KVM virtio drivers detected in System32"})
	}
	if isQEMU, _ := v.CheckQEMU(); isQEMU {
		results = append(results, models.CheckResult{Category: models.CategoryAntiVM, Name: "QEMU Drivers", Detected: true, Severity: models.SeverityHigh, Details: "QEMU guest agent/drivers detected in System32"})
	}
	if isParallels, _ := v.CheckParallels(); isParallels {
		results = append(results, models.CheckResult{Category: models.CategoryAntiVM, Name: "Parallels Drivers", Detected: true, Severity: models.SeverityHigh, Details: "Parallels drivers detected in System32"})
	}

	// VM Files & Drivers
	if v.CheckVMFiles() {
		results = append(results, models.CheckResult{Category: models.CategoryAntiVM, Name: "VM Artifact Files", Detected: true, Severity: models.SeverityHigh, Details: "Known VM driver/guest addition files exist on disk"})
	}

	// Named Pipes
	if v.CheckNamedPipes() {
		results = append(results, models.CheckResult{Category: models.CategoryAntiVM, Name: "Suspicious Named Pipes", Detected: true, Severity: models.SeverityHigh, Details: "Hypervisor or sandbox named pipes accessible"})
	}

	// Sandbox DLLs
	if v.CheckSandboxie() {
		results = append(results, models.CheckResult{Category: models.CategoryAntiVM, Name: "Sandboxie", Detected: true, Severity: models.SeverityHigh, Details: "SbieDll.dll injected into process"})
	}
	if v.CheckComodoSandbox() {
		results = append(results, models.CheckResult{Category: models.CategoryAntiVM, Name: "Comodo Sandbox", Detected: true, Severity: models.SeverityHigh, Details: "Comodo sandbox DLLs detected"})
	}
	if v.CheckCuckooSandbox() {
		results = append(results, models.CheckResult{Category: models.CategoryAntiVM, Name: "Cuckoo Sandbox", Detected: true, Severity: models.SeverityHigh, Details: "cuckoomon.dll detected"})
	}
	if v.CheckWine() {
		results = append(results, models.CheckResult{Category: models.CategoryAntiVM, Name: "Wine Emulation", Detected: true, Severity: models.SeverityHigh, Details: "Wine environment detected"})
	}

	// ANY.RUN Sandbox
	if v.CheckAnyRun() {
		results = append(results, models.CheckResult{Category: models.CategoryAntiVM, Name: "ANY.RUN Sandbox", Detected: true, Severity: models.SeverityCritical, Details: "Known ANY.RUN sandbox MachineGuid identified in registry"})
	}

	// Blacklisted Usernames
	if v.CheckBlacklistedUsernames() {
		results = append(results, models.CheckResult{Category: models.CategoryAntiVM, Name: "Sandbox Username", Detected: true, Severity: models.SeverityHigh, Details: fmt.Sprintf("Known sandbox username detected: %s", os.Getenv("USERNAME"))})
	}

	// Port Connectors
	if zeroPorts, err := v.CheckPortConnectors(); err == nil && zeroPorts {
		results = append(results, models.CheckResult{Category: models.CategoryHardware, Name: "Motherboard Port Connectors", Detected: true, Severity: models.SeverityMedium, Details: "No physical motherboard port connectors detected"})
	}

	// USB Devices History
	if noUSB, err := v.CheckUSBDevices(); err == nil && noUSB {
		results = append(results, models.CheckResult{Category: models.CategoryHardware, Name: "USB Storage History", Detected: true, Severity: models.SeverityLow, Details: "No historical USB storage devices detected in USBSTOR registry"})
	}

	return results
}
