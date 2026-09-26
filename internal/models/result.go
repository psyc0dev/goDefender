package models

import (
	"fmt"
	"strings"
)

type CheckCategory string

const (
	CategoryAntiVM    CheckCategory = "Anti-VM"
	CategoryAntiDebug CheckCategory = "Anti-Debug"
	CategoryAntiDLL   CheckCategory = "Anti-DLL"
	CategoryHooks     CheckCategory = "API Hooks"
	CategoryHardware  CheckCategory = "Hardware/Firmware"
	CategoryTiming    CheckCategory = "Timing/Execution"
)

type Severity string

const (
	SeverityInfo     Severity = "INFO"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

type CheckResult struct {
	Category    CheckCategory `json:"category"`
	Name        string        `json:"name"`
	Detected    bool          `json:"detected"`
	Severity    Severity      `json:"severity"`
	Details     string        `json:"details,omitempty"`
	Error       error         `json:"error,omitempty"`
}

type Report struct {
	Results     []CheckResult `json:"results"`
	TotalChecks int           `json:"total_checks"`
	ThreatCount int           `json:"threat_count"`
	PassedCount int           `json:"passed_count"`
	ErrorCount  int           `json:"error_count"`
}

func NewReport() *Report {
	return &Report{
		Results: make([]CheckResult, 0),
	}
}

func (r *Report) Add(res CheckResult) {
	r.Results = append(r.Results, res)
	r.TotalChecks++
	if res.Error != nil {
		r.ErrorCount++
	} else if res.Detected {
		r.ThreatCount++
	} else {
		r.PassedCount++
	}
}

func (r *Report) Summary() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("🛡️ Scan Summary: %d total checks | %d threats detected | %d passed | %d errors\n",
		r.TotalChecks, r.ThreatCount, r.PassedCount, r.ErrorCount))
	sb.WriteString(strings.Repeat("=", 65) + "\n")
	for _, res := range r.Results {
		if res.Error != nil {
			sb.WriteString(fmt.Sprintf("[⚠️ ERROR] [%s] %s: %v\n", res.Category, res.Name, res.Error))
		} else if res.Detected {
			sb.WriteString(fmt.Sprintf("[🚨 THREAT - %s] [%s] %s: %s\n", res.Severity, res.Category, res.Name, res.Details))
		} else {
			sb.WriteString(fmt.Sprintf("[✅ PASS] [%s] %s\n", res.Category, res.Name))
		}
	}
	return sb.String()
}
