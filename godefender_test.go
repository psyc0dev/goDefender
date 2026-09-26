package godefender

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/psyc0dev/goDefender/internal/hooks"
	"github.com/psyc0dev/goDefender/internal/models"
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

func TestQuickCheck(t *testing.T) {
	// Should execute without panics
	_ = QuickCheck()
}

func TestInspectPrologueBytes(t *testing.T) {
	cases := []struct {
		name       string
		bytes      []byte
		wantHook   bool
		wantReason string
	}{
		{
			name:     "Normal x64 prologue (push rbp; mov rbp, rsp)",
			bytes:    []byte{0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20},
			wantHook: false,
		},
		{
			name:       "INT3 Breakpoint trap (0xCC)",
			bytes:      []byte{0xCC, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90},
			wantHook:   true,
			wantReason: "INT3",
		},
		{
			name:       "NOP Sled (0x90 0x90)",
			bytes:      []byte{0x90, 0x90, 0x55, 0x48, 0x89, 0xE5, 0x00, 0x00},
			wantHook:   true,
			wantReason: "NOP",
		},
		{
			name:       "JMP rel32 (0xE9 near jump)",
			bytes:      []byte{0xE9, 0x10, 0x20, 0x30, 0x40, 0x00, 0x00, 0x00},
			wantHook:   true,
			wantReason: "near jump",
		},
		{
			name:       "JMP rel8 (0xEB short jump)",
			bytes:      []byte{0xEB, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			wantHook:   true,
			wantReason: "short jump",
		},
		{
			name:       "x64 RIP-relative indirect jump (FF 25)",
			bytes:      []byte{0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			wantHook:   true,
			wantReason: "indirect",
		},
		{
			name: "x64 absolute jump (mov rax, imm64; jmp rax)",
			bytes: []byte{
				0x48, 0xB8, 0x78, 0x56, 0x34, 0x12, 0x00, 0x00,
				0x00, 0x00, 0xFF, 0xE0, 0x00, 0x00, 0x00, 0x00,
			},
			wantHook:   true,
			wantReason: "MOV RAX",
		},
		{
			name: "Legitimate mov rax instruction (not followed by jmp)",
			bytes: []byte{
				0x48, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x48, 0x01, 0xD8, 0xC3, 0x00, 0x00,
			},
			wantHook: false,
		},
		{
			name: "PUSH imm32; RET hook (0x68 ... 0xC3)",
			bytes: []byte{
				0x68, 0x11, 0x22, 0x33, 0x44, 0xC3, 0x00, 0x00,
			},
			wantHook:   true,
			wantReason: "PUSH-RET",
		},
		{
			name:     "Too short slice",
			bytes:    []byte{0x55},
			wantHook: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotHook, gotReason := hooks.InspectPrologueBytes(tc.bytes)
			if gotHook != tc.wantHook {
				t.Fatalf("InspectPrologueBytes() gotHook=%v, want=%v", gotHook, tc.wantHook)
			}
			if tc.wantHook && !strings.Contains(gotReason, tc.wantReason) {
				t.Errorf("InspectPrologueBytes() reason %q does not contain %q", gotReason, tc.wantReason)
			}
		})
	}
}

func TestJSONSerialization(t *testing.T) {
	rep := models.NewReport()
	rep.Add(models.CheckResult{
		Category: models.CategoryAntiDebug,
		Name:     "TestCheckPass",
		Detected: false,
		Severity: models.SeverityInfo,
		Details:  "Pass info",
	})
	rep.Add(models.CheckResult{
		Category: models.CategoryAntiDebug,
		Name:     "TestCheckThreat",
		Detected: true,
		Severity: models.SeverityHigh,
		Details:  "Threat found",
	})
	rep.Add(models.CheckResult{
		Category: models.CategoryAntiDebug,
		Name:     "TestCheckError",
		Detected: false,
		Severity: models.SeverityLow,
		Error:    errors.New("sample error occurred"),
	})

	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("Failed to marshal Report to JSON: %v", err)
	}

	jsonStr := string(data)
	if !strings.Contains(jsonStr, "sample error occurred") {
		t.Errorf("JSON should serialize error string, got: %s", jsonStr)
	}
	if !strings.Contains(jsonStr, "Threat found") {
		t.Errorf("JSON should contain threat details, got: %s", jsonStr)
	}
}

func TestReportSummary(t *testing.T) {
	rep := models.NewReport()
	rep.Add(models.CheckResult{Category: models.CategoryAntiDebug, Name: "CheckA", Detected: false})
	rep.Add(models.CheckResult{Category: models.CategoryAntiDebug, Name: "CheckB", Detected: true, Severity: models.SeverityCritical, Details: "Alert"})
	rep.Add(models.CheckResult{Category: models.CategoryAntiDebug, Name: "CheckC", Error: errors.New("fail")})

	summary := rep.Summary()
	if !strings.Contains(summary, "[✅ PASS]") {
		t.Errorf("Summary missing PASS tag: %s", summary)
	}
	if !strings.Contains(summary, "[🚨 THREAT - CRITICAL]") {
		t.Errorf("Summary missing THREAT tag: %s", summary)
	}
	if !strings.Contains(summary, "[⚠️ ERROR]") {
		t.Errorf("Summary missing ERROR tag: %s", summary)
	}
}

func BenchmarkAudit(b *testing.B) {
	eng := New()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = eng.RunDiagnosticReport()
	}
}
