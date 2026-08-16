package godefender

import (
	"github.com/EvilBytecode/GoDefender/internal/defender"
	"github.com/EvilBytecode/GoDefender/internal/models"
)

// Re-export core types for convenient client consumption.
type CheckCategory = models.CheckCategory
type Severity = models.Severity
type CheckResult = models.CheckResult
type Report = models.Report

const (
	CategoryAntiVM    = models.CategoryAntiVM
	CategoryAntiDebug = models.CategoryAntiDebug
	CategoryAntiDLL   = models.CategoryAntiDLL
	CategoryHooks     = models.CategoryHooks
	CategoryHardware  = models.CategoryHardware
	CategoryTiming    = models.CategoryTiming

	SeverityInfo     = models.SeverityInfo
	SeverityLow      = models.SeverityLow
	SeverityMedium   = models.SeverityMedium
	SeverityHigh     = models.SeverityHigh
	SeverityCritical = models.SeverityCritical
)

// Engine is the central interface for running scans and applying active mitigations.
type Engine = defender.Engine

// New initializes and returns a new GoDefender engine instance.
func New() *Engine {
	return defender.New()
}

// QuickCheck runs the full diagnostic suite and returns true if any threats are detected.
func QuickCheck() bool {
	report := New().RunDiagnosticReport()
	return report.ThreatCount > 0
}

// RunAudit executes all security checks and returns the detailed Report.
func RunAudit() *models.Report {
	return New().RunDiagnosticReport()
}

// ProtectAndAudit applies in-memory mitigations first, then executes the audit suite.
func ProtectAndAudit() ([]models.CheckResult, *models.Report) {
	eng := New()
	mitigations := eng.ApplyActiveDefenses()
	report := eng.RunDiagnosticReport()
	return mitigations, report
}
