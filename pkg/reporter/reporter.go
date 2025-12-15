// Copyright 2025 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package reporter

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/fatih/color"
	"github.com/interlynk-io/sbomdelta/pkg/bom"
	"github.com/interlynk-io/sbomdelta/pkg/vuln"
)

func PrintSummaryMetrics(metrics map[string]int, removedPkgs, addedPkgs, commonPkgs []bom.PkgKey) {
	title := color.New(color.FgCyan, color.Bold).SprintFunc()
	// strong := color.New(color.FgWhite, color.Bold).SprintFunc()
	ok := color.New(color.FgGreen).SprintFunc()
	warn := color.New(color.FgYellow).SprintFunc()
	bad := color.New(color.FgRed).SprintFunc()

	// fmt.Println(title("=== SBOM / Vulnerability Delta Summary ==="))
	fmt.Println()

	fmt.Println(title("=== Raw Vulnerability Counts ==="))
	fmt.Printf("  Upstream total CVEs:   %d\n", metrics["total_cves_upstream"])
	fmt.Printf("  Hardened total CVEs:   %d\n", metrics["total_cves_hardened"])
	fmt.Println()

	fmt.Println(title("=== Package Delta (What Actually Changed) ==="))
	fmt.Printf("  Packages removed in hardened: %s\n", ok(len(removedPkgs)))
	fmt.Printf("  Packages added in hardened:   %s\n", warn(len(addedPkgs)))
	fmt.Printf("  Packages common in both:      %d\n", len(commonPkgs))
	fmt.Println()

	fmt.Println(title("=== Impact of Package Changes on CVEs ==="))
	fmt.Printf("  CVEs removed because packages disappeared: %s\n", ok(metrics["cves_from_removed_pkgs"]))
	fmt.Printf("  CVEs added because packages appeared:      %s\n", bad(metrics["cves_from_added_pkgs"]))
	fmt.Printf("  CVEs on common packages:                   %d\n", metrics["cves_on_common_pkgs"])
	fmt.Println()

	fmt.Println(title("=== CVE Delta (Root-Cause Breakdown) ==="))
	fmt.Printf("  Only in upstream:  %s\n", ok(metrics["only_upstream"]))
	fmt.Printf("  Only in hardened:  %s\n", bad(metrics["only_hardened"]))
	fmt.Printf("  Present in both:   %d\n", metrics["both"])
	fmt.Printf("  High/Crit removed: %s\n", ok(metrics["high_crit_removed"]))
	fmt.Printf("  High/Crit added:   %s\n", bad(metrics["high_crit_new"]))
	fmt.Println()
}

// stripANSI removes ANSI escape sequences so we can compute visible length.
var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func stripANSI(s string) string {
	return ansiRE.ReplaceAllString(s, "")
}

// padRightVisible pads `s` with spaces so that its visible length equals width.
func padRightVisible(s string, width int) string {
	visible := len(stripANSI(s))
	if visible >= width {
		return s
	}
	return s + strings.Repeat(" ", width-visible)
}

func PrintDeltaTable(rows []vuln.DeltaRow) {
	if len(rows) == 0 {
		fmt.Println("No vulnerability deltas to display.")
		return
	}

	// color helpers
	header := color.New(color.FgMagenta, color.Bold).SprintFunc()
	ok := color.New(color.FgGreen).SprintFunc()
	warn := color.New(color.FgYellow).SprintFunc()
	bad := color.New(color.FgRed).SprintFunc()
	neutral := color.New(color.FgWhite).SprintFunc()

	fmt.Println(header("=== Vulnerability Delta Detail ==="))

	// Column widths (tune these if you need more/less)
	const (
		colPkgWidth    = 40
		colCVEWidth    = 18
		colStatusWidth = 22
		colUpWidth     = 10
		colHardWidth   = 10
		totalLineWidth = colPkgWidth + colCVEWidth + colStatusWidth + colUpWidth + colHardWidth + 5
	)

	// header row
	fmt.Printf("%-*s %-*s %-*s %-*s %-*s\n",
		colPkgWidth, "PACKAGE@VERSION",
		colCVEWidth, "CVE",
		colStatusWidth, "STATUS",
		colUpWidth, "UPSTREAM",
		colHardWidth, "HARDENED",
	)
	fmt.Println(strings.Repeat("-", totalLineWidth))

	for _, r := range rows {
		// choose colorized status string
		var statusColored string
		switch r.Status {
		case vuln.StatusOnlyUpstream:
			statusColored = ok(string(r.Status))
		case vuln.StatusOnlyHardened:
			statusColored = bad(string(r.Status))
		case vuln.StatusBothDiffSeverity:
			statusColored = warn(string(r.Status))
		default:
			statusColored = neutral(string(r.Status))
		}

		// pad status based on visible length (strip ANSI)
		statusCell := padRightVisible(statusColored, colStatusWidth)

		// upstream / hardened severity - show "-" if empty
		upS := string(r.SeverityUp)
		if upS == "" || upS == "UNKNOWN" {
			upS = "-"
		}
		hdS := string(r.SeverityHardened)
		if hdS == "" || hdS == "UNKNOWN" {
			hdS = "-"
		}

		// package key as string
		pkgStr := string(r.PkgKey)

		// print the row using fixed-width columns *for non-colored* fields,
		// insert already-padded statusCell (which may contain ANSI codes)
		fmt.Printf("%-*s %-*s %s %-*s %-*s\n",
			colPkgWidth, pkgStr,
			colCVEWidth, r.CVE,
			statusCell,
			colUpWidth, upS,
			colHardWidth, hdS,
		)
	}
	fmt.Println()
}
