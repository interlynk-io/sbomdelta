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

package delta

import (
	"context"
	"fmt"

	"github.com/interlynk-io/sbomdelta/pkg/bom"
	"github.com/interlynk-io/sbomdelta/pkg/reporter"
	"github.com/interlynk-io/sbomdelta/pkg/types"
	"github.com/interlynk-io/sbomdelta/pkg/vuln"
)

// simple implementation; later to implement a richer backport matcher.
type backportIgnoreSet struct {
	m map[vuln.VulnKey]struct{}
}

func (b *backportIgnoreSet) Matches(pkg bom.PkgKey, cve string) bool {
	if b == nil {
		return false
	}
	_, ok := b.m[vuln.VulnKey{Pkg: pkg, CVE: cve}]
	return ok
}

func RunEval(_ context.Context, cfg *types.Config) error {
	if cfg.BackportVulnPath != "" {
		fmt.Printf("Backport Vuln:  %s (%s)\n", cfg.BackportVulnPath, cfg.BackportVulnFormat)
	} else {
		fmt.Println("Backport Vuln:  (none)")
	}

	// Next steps:
	// 1. sbom.LoadSBOM(...)
	// 2. vuln.LoadVulns(...)
	// 3. delta.ComputePackageDelta(...)
	// 4. delta.ComputeVulnDelta(...)
	// 5. reporter.PrintSummaryMetrics(...)
	// 6. reporter.PrintDeltaTable(...)

	// 1. Load SBOMs
	upstreamPkgs, err := bom.NewLoadSBOM(cfg.UpstreamSBOMPath)
	if err != nil {
		return fmt.Errorf("load upstream SBOM: %w", err)
	}

	hardendPkgs, err := bom.NewLoadSBOM(cfg.HardenedSBOMPath)
	if err != nil {
		return fmt.Errorf("load hardened SBOM: %w", err)
	}

	// 2. Load vuln reports
	upstreamVulns, err := vuln.LoadVulns(cfg.UpstreamVulnPath, cfg.UpstreamVulnFormat)
	if err != nil {
		return fmt.Errorf("load upstream vuln report: %w", err)
	}

	hardendVulns, err := vuln.LoadVulns(cfg.HardenedVulnPath, cfg.HardenedVulnFormat)
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
		m := make(map[vuln.VulnKey]struct{}, len(bpVulns))
		for k := range bpVulns {
			m[k] = struct{}{}
		}
		ignore = &backportIgnoreSet{m: m}
	}

	// 3. Package-level delta
	removedPkgs, addedPkgs, commonPkgs := ComputePackageDelta(upstreamPkgs, hardendPkgs)

	// 4. Vuln-level delta
	deltas, metrics := ComputeVulnDelta(upstreamVulns, hardendVulns, ignore)

	// 4.5. Link package delta → CVE delta
	metrics = EnrichMetricsWithPackageImpact(metrics, deltas, removedPkgs, addedPkgs, commonPkgs)

	// 5. Reporting
	reporter.PrintSummaryMetrics(metrics, removedPkgs, addedPkgs, commonPkgs)
	reporter.PrintDeltaTable(deltas)

	return nil
}
