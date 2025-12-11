package delta

import (
	"context"
	"fmt"

	"github.com/viveksahu26/sbomdelta/pkg/reporter"
	"github.com/viveksahu26/sbomdelta/pkg/sbom"
	"github.com/viveksahu26/sbomdelta/pkg/types"
	"github.com/viveksahu26/sbomdelta/pkg/vuln"
)

// simple implementation; later you can implement a richer backport matcher.
type backportIgnoreSet struct {
	m map[types.VulnKey]struct{}
}

func (b *backportIgnoreSet) Matches(pkg types.PkgKey, cve string) bool {
	if b == nil {
		return false
	}
	_, ok := b.m[types.VulnKey{Pkg: pkg, CVE: cve}]
	return ok
}

func RunEval(_ context.Context, cfg *types.Config) error {
	// // For now, just confirm we parsed everything correctly.
	// fmt.Println("== delta eval ==")
	// fmt.Printf("Upstream SBOM:  %s (%s)\n", cfg.UpstreamSBOMPath, cfg.UpstreamSBOMFormat)
	// fmt.Printf("Hardened SBOM:  %s (%s)\n", cfg.HardenedSBOMPath, cfg.HardenedSBOMFormat)
	// fmt.Printf("Upstream Vuln:  %s (%s)\n", cfg.UpstreamVulnPath, cfg.UpstreamVulnFormat)
	// fmt.Printf("Hardened Vuln:  %s (%s)\n", cfg.HardenedVulnPath, cfg.HardenedVulnFormat)

	if cfg.BackportVulnPath != "" {
		fmt.Printf("Backport Vuln:  %s (%s)\n", cfg.BackportVulnPath, cfg.BackportVulnFormat)
	} else {
		fmt.Println("Backport Vuln:  (none)")
	}

	// Next steps (we'll implement in later steps):
	// 1. sbom.LoadSBOM(...)
	// 2. vuln.LoadVulns(...)
	// 3. delta.ComputePackageDelta(...)
	// 4. delta.ComputeVulnDelta(...)
	// 5. reporter.PrintSummaryMetrics(...)
	// 6. reporter.PrintDeltaTable(...)

	// 1. Load SBOMs
	upPkgs, err := sbom.LoadSBOM(cfg.UpstreamSBOMPath, cfg.UpstreamSBOMFormat)
	if err != nil {
		return fmt.Errorf("load upstream SBOM: %w", err)
	}

	hdPkgs, err := sbom.LoadSBOM(cfg.HardenedSBOMPath, cfg.HardenedSBOMFormat)
	if err != nil {
		return fmt.Errorf("load hardened SBOM: %w", err)
	}

	// 2. Load vuln reports
	upVulns, err := vuln.LoadVulns(cfg.UpstreamVulnPath, cfg.UpstreamVulnFormat)
	if err != nil {
		return fmt.Errorf("load upstream vuln report: %w", err)
	}

	hdVulns, err := vuln.LoadVulns(cfg.HardenedVulnPath, cfg.HardenedVulnFormat)
	if err != nil {
		return fmt.Errorf("load hardened vuln report: %w", err)
	}

	var ignore BackportIgnore
	if cfg.BackportVulnPath != "" {
		bpVulns, err := vuln.LoadVulns(cfg.BackportVulnPath, cfg.BackportVulnFormat)
		if err != nil {
			return fmt.Errorf("load backport vuln report: %w", err)
		}

		// convert to simple set
		m := make(map[types.VulnKey]struct{}, len(bpVulns))
		for k := range bpVulns {
			m[k] = struct{}{}
		}
		ignore = &backportIgnoreSet{m: m}
	}

	// 3. Package-level delta
	removedPkgs, addedPkgs, commonPkgs := ComputePackageDelta(upPkgs, hdPkgs)

	// 4. Vuln-level delta
	deltas, metrics := ComputeVulnDelta(upVulns, hdVulns, ignore)

	// 4.5. Link package delta → CVE delta
	metrics = EnrichMetricsWithPackageImpact(metrics, deltas, removedPkgs, addedPkgs, commonPkgs)

	// 5. Reporting
	reporter.PrintSummaryMetrics(metrics, removedPkgs, addedPkgs, commonPkgs)
	reporter.PrintDeltaTable(deltas)

	return nil
}
