package reporter

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/viveksahu26/sbomdelta/pkg/types"
)

func PrintSummaryMetrics(metrics map[string]int, removedPkgs, addedPkgs, commonPkgs []types.PkgKey) {
	title := color.New(color.FgCyan, color.Bold).SprintFunc()
	strong := color.New(color.FgWhite, color.Bold).SprintFunc()
	ok := color.New(color.FgGreen).SprintFunc()
	warn := color.New(color.FgYellow).SprintFunc()
	bad := color.New(color.FgRed).SprintFunc()

	fmt.Println(title("=== SBOM / Vulnerability Delta Summary ==="))
	fmt.Println()

	fmt.Printf("%s\n", strong("Packages Delta:"))
	fmt.Printf("  Removed in hardened: %s\n", ok(len(removedPkgs)))
	fmt.Printf("  Added in hardened:   %s\n", warn(len(addedPkgs)))
	fmt.Printf("  Common:              %d\n", len(commonPkgs))
	fmt.Println()

	fmt.Printf("%s\n", strong("CVEs (raw counts):"))
	fmt.Printf("  Upstream total:   %d\n", metrics["total_cves_upstream"])
	fmt.Printf("  Hardened total:   %d\n", metrics["total_cves_hardened"])
	fmt.Printf("  Only upstream:    %s\n", ok(metrics["only_upstream"]))
	fmt.Printf("  Only hardened:    %s\n", bad(metrics["only_hardened"]))
	fmt.Printf("  Present in both:  %d\n", metrics["both"])
	fmt.Printf("  High/Crit removed:%s\n", ok(metrics["high_crit_removed"]))
	fmt.Printf("  High/Crit new:    %s\n", bad(metrics["high_crit_new"]))
	fmt.Println()

	fmt.Printf("%s\n", strong("Affect of package delta on CVE:"))
	fmt.Printf("  CVEs from removed packages: %s\n", ok(metrics["cves_from_removed_pkgs"]))
	fmt.Printf("  CVEs from added packages:   %s\n", bad(metrics["cves_from_added_pkgs"]))
	fmt.Printf("  CVEs on common packages:    %d\n", metrics["cves_on_common_pkgs"])
	fmt.Println()
}

func PrintDeltaTable(rows []types.DeltaRow) {
	if len(rows) == 0 {
		fmt.Println("No vulnerability deltas to display.")
		return
	}

	header := color.New(color.FgMagenta, color.Bold).SprintFunc()
	ok := color.New(color.FgGreen).SprintFunc()
	warn := color.New(color.FgYellow).SprintFunc()
	bad := color.New(color.FgRed).SprintFunc()
	neutral := color.New(color.FgWhite).SprintFunc()

	fmt.Println(header("=== Vulnerability Delta Detail ==="))
	fmt.Printf("%-40s %-20s %-22s %-10s %-10s\n",
		"PACKAGE@VERSION", "CVE", "STATUS", "UPSTREAM", "HARDENED")
	fmt.Println(strings.Repeat("-", 110))

	for _, r := range rows {
		var statusStr string
		switch r.Status {
		case types.StatusOnlyUpstream:
			statusStr = ok(string(r.Status))
		case types.StatusOnlyHardened:
			statusStr = bad(string(r.Status))
		case types.StatusBothDiffSeverity:
			statusStr = warn(string(r.Status))
		default:
			statusStr = neutral(string(r.Status))
		}

		fmt.Printf("%-40s %-20s %-22s %-10s %-10s\n",
			string(r.PkgKey), r.CVE, statusStr,
			r.SeverityUp, r.SeverityHardened)
	}
	fmt.Println()
}
