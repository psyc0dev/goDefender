package godefender

import (
	"testing"
)

func TestEngineInitialization(t *testing.T) {
	eng := New()
	if eng == nil {
		t.Fatal("Expected New() to return a non-nil Engine")
	}
}

func TestRunAudit(t *testing.T) {
	report := RunAudit()
	if report == nil {
		t.Fatal("Expected RunAudit() to return a non-nil Report")
	}

	if report.TotalChecks == 0 {
		t.Errorf("Expected TotalChecks > 0, got %d", report.TotalChecks)
	}

	t.Logf("Total checks executed: %d (Threats: %d, Passed: %d, Errors: %d)",
		report.TotalChecks, report.ThreatCount, report.PassedCount, report.ErrorCount)
}

func BenchmarkAudit(b *testing.B) {
	eng := New()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eng.RunDiagnosticReport()
	}
}
