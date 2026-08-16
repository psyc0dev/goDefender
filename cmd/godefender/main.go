package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	godefender "github.com/psyc0dev/goDefender"
)

func main() {
	jsonOutput := flag.Bool("json", false, "Output results in JSON format")
	applyDefenses := flag.Bool("protect", false, "Apply active in-memory defenses (DLL mitigation, anti-debug patches)")
	flag.Parse()

	engine := godefender.New()

	if *applyDefenses {
		mitigations := engine.ApplyActiveDefenses()
		if !*jsonOutput {
			fmt.Println("🛡️ Applying Active Protections:")
			for _, m := range mitigations {
				if m.Error != nil {
					fmt.Printf("  [⚠️ ERROR] %s: %v\n", m.Name, m.Error)
				} else {
					fmt.Printf("  [🛡️ APPLIED] %s: %s\n", m.Name, m.Details)
				}
			}
			fmt.Println()
		}
	}

	report := engine.RunDiagnosticReport()

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			fmt.Fprintf(os.Stderr, "Error formatting JSON: %v\n", err)
			os.Exit(1)
		}
		return
	}

	fmt.Print(report.Summary())

	if report.ThreatCount > 0 {
		os.Exit(2)
	}
}
