package defender

import (
	"sync"

	"github.com/EvilBytecode/GoDefender/internal/antidebug"
	"github.com/EvilBytecode/GoDefender/internal/antidll"
	"github.com/EvilBytecode/GoDefender/internal/antivm"
	"github.com/EvilBytecode/GoDefender/internal/hooks"
	"github.com/EvilBytecode/GoDefender/internal/models"
)

type Engine struct {
	VMDetector   *antivm.VMDetector
	Debugger     *antidebug.Debugger
	DLLProtector *antidll.DLLProtector
	HookDetector *hooks.HookDetector
}

func New() *Engine {
	return &Engine{
		VMDetector:   antivm.New(),
		Debugger:     antidebug.New(),
		DLLProtector: antidll.New(),
		HookDetector: hooks.New(),
	}
}

// RunDiagnosticReport runs the entire security audit suite concurrently and produces a structured Report.
func (e *Engine) RunDiagnosticReport() *models.Report {
	report := models.NewReport()

	var (
		wg         sync.WaitGroup
		vmResults  []models.CheckResult
		dbgResults []models.CheckResult
		hookResult models.CheckResult
	)

	wg.Add(3)

	// 1. Anti-VM & Hardware Checks
	go func() {
		defer wg.Done()
		vmResults = e.VMDetector.RunAllChecks()
	}()

	// 2. Anti-Debug Checks
	go func() {
		defer wg.Done()
		dbgResults = e.Debugger.RunAllChecks()
	}()

	// 3. API Hook Integrity Checks
	go func() {
		defer wg.Done()
		hookResult = e.HookDetector.CheckHookIntegrity()
	}()

	wg.Wait()

	for _, res := range vmResults {
		report.Add(res)
	}
	for _, res := range dbgResults {
		report.Add(res)
	}
	report.Add(hookResult)

	return report
}

// ApplyActiveDefenses applies in-memory mitigations such as binary signature policies and anti-debug function patches.
func (e *Engine) ApplyActiveDefenses() []models.CheckResult {
	var results []models.CheckResult

	// Set Process Mitigation Policy (Microsoft Binaries Only)
	if err := e.DLLProtector.PreventDLLInjection(); err != nil {
		results = append(results, models.CheckResult{
			Category: models.CategoryAntiDLL,
			Name:     "Binary Signature Mitigation Policy",
			Error:    err,
		})
	} else {
		results = append(results, models.CheckResult{
			Category: models.CategoryAntiDLL,
			Name:     "Binary Signature Mitigation Policy",
			Severity: models.SeverityInfo,
			Details:  "MicrosoftSignedOnly mitigation policy activated",
		})
	}

	// Anti-Debug Breakpoint Patching
	if e.Debugger.PatchAntiDebug() {
		results = append(results, models.CheckResult{
			Category: models.CategoryAntiDebug,
			Name:     "Anti-Debug Memory Patches",
			Severity: models.SeverityInfo,
			Details:  "DbgUiRemoteBreakin and DbgBreakPoint patched",
		})
	}

	// Debug Filter State Protection
	if e.Debugger.SetDebugFilterState() {
		results = append(results, models.CheckResult{
			Category: models.CategoryAntiDebug,
			Name:     "Debug Filter State",
			Severity: models.SeverityInfo,
			Details:  "NtSetDebugFilterState mask applied",
		})
	}

	return results
}
