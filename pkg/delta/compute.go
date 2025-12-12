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
	"sort"

	"github.com/interlynk-io/sbomdelta/pkg/bom"
	"github.com/interlynk-io/sbomdelta/pkg/vuln"
)

// ComputePackageDelta compute packages removed from hardened, added into hardened and common in both
func ComputePackageDelta(upstreamPkgs, hardendPkgs map[bom.PkgKey]bom.Package) (removed, added, common []bom.PkgKey) {
	// catalog variable stores all upstream package keys
	// and hardened package keys into it.
	catalog := make(map[bom.PkgKey]struct{})

	for key := range upstreamPkgs {
		catalog[key] = struct{}{}
	}

	for key := range hardendPkgs {
		catalog[key] = struct{}{}
	}

	for key := range catalog {

		// check whther the package key is present in upstream packages list
		_, inUpStream := upstreamPkgs[key]

		// check whther the package key is present in hardened packages list
		_, inHardened := hardendPkgs[key]

		switch {

		// package is present in upstream but absent in hardened:
		// that means removed from hardened
		case inUpStream && !inHardened:
			removed = append(removed, key)

		// package is absent in upstream but present in hardened
		// that means new packages added in hardened
		case !inUpStream && inHardened:
			added = append(added, key)

		// package is present in both upstream as well as hardened
		// that means common in both
		case inUpStream && inHardened:
			common = append(common, key)
		}
	}

	return removed, added, common
}

// Row is one (pkg, cve) comparison result.
type RowStatus string

// Metrics is aggregated view over DeltaRows.
type Metrics struct {
	TotalCVEsUpstream int
	TotalCVEsHardened int

	OnlyUpstream int
	OnlyHardened int
	Both         int

	HighCritRemoved int
	HighCritNew     int

	BackportIgnored int // optional
}

// BackportIgnore describes which (pkg, CVE) pairs to ignore (optional).
type BackportIgnore interface {
	Matches(pkg bom.PkgKey, cve string) bool
}

// ComputeVulnDelta does the vuln delta, including optional backport ignore.
func ComputeVulnDelta(upstreamVulns, hardendVulns map[vuln.VulnKey]vuln.VulnFinding, ignore BackportIgnore) ([]vuln.DeltaRow, map[string]int) {
	deltas := []vuln.DeltaRow{}

	// catalog variable contains all vulnerabilities keys: upstream vuln + hardend vuln keys
	catalog := make([]vuln.VulnKey, 0, len(upstreamVulns)+len(hardendVulns))

	// seen variable avoid storing duplicate keys in catalog
	seen := make(map[vuln.VulnKey]struct{})

	for key := range upstreamVulns {
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			catalog = append(catalog, key)
		}
	}

	for key := range hardendVulns {
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			catalog = append(catalog, key)
		}
	}

	metrics := map[string]int{
		"total_cves_upstream": len(upstreamVulns),
		"total_cves_hardened": len(hardendVulns),
		"only_upstream":       0,
		"only_hardened":       0,
		"both":                0,
		"high_crit_removed":   0,
		"high_crit_new":       0,
		// "cves_from_removed_pkgs": 0,
		// "cves_from_added_pkgs":   0,
		// "cves_on_common_pkgs":    0,
	}

	isHighCrit := func(s vuln.Severity) bool {
		return s == "HIGH" || s == "CRITICAL"
	}

	for _, key := range catalog {
		upFinding, hasUpVuln := upstreamVulns[key]
		hardFinding, hasHardVuln := hardendVulns[key]

		pkgKey := key.Pkg
		cve := key.CVE

		if ignore != nil && ignore.Matches(pkgKey, cve) {
			continue
		}

		delta := vuln.DeltaRow{
			PkgKey: pkgKey,
			CVE:    cve,
		}

		switch {

		// vulnerability is present in Upstream but absent in hardened
		case hasUpVuln && !hasHardVuln:
			delta.Status = vuln.StatusOnlyUpstream
			delta.SeverityUp = upFinding.Severity
			metrics["only_upstream"]++

			if isHighCrit(upFinding.Severity) {
				metrics["high_crit_removed"]++
			}

		// vulnerability is absent in Upstream but present in hardened
		case !hasUpVuln && hasHardVuln:
			delta.Status = vuln.StatusOnlyHardened
			delta.SeverityHardened = hardFinding.Severity
			metrics["only_hardened"]++

			if isHighCrit(hardFinding.Severity) {
				metrics["high_crit_new"]++
			}

		// vulnerability is present in both Upstream and hardened
		case hasUpVuln && hasHardVuln:
			delta.SeverityUp = upFinding.Severity
			delta.SeverityHardened = hardFinding.Severity

			if upFinding.Severity == hardFinding.Severity {
				delta.Status = vuln.StatusBothSameSeverity
			} else {
				delta.Status = vuln.StatusBothDiffSeverity
			}

			metrics["both"]++

		//
		default:
			// shouldn't happen; means no entry in either map
			continue
		}

		deltas = append(deltas, delta)
	}

	// Sort rows for stable output
	sort.Slice(deltas, func(i, j int) bool {
		if deltas[i].PkgKey == deltas[j].PkgKey {
			return deltas[i].CVE < deltas[j].CVE
		}
		return deltas[i].PkgKey < deltas[j].PkgKey
	})

	return deltas, metrics
}

func ComputeLinkedPackageAndCVEDelta(removedPkgs, addedPkgs, commonPkgs []bom.PkgKey, deltas []vuln.DeltaRow) {
	removedSet := make(map[bom.PkgKey]struct{})
	addedSet := make(map[bom.PkgKey]struct{})
	commonSet := make(map[bom.PkgKey]struct{})

	for _, k := range removedPkgs {
		removedSet[k] = struct{}{}
	}

	for _, k := range addedPkgs {
		addedSet[k] = struct{}{}
	}

	for _, k := range commonPkgs {
		commonSet[k] = struct{}{}
	}
}

// func makePkgSet(keys []types.PkgKey) map[types.PkgKey]struct{} {
// 	set := make(map[types.PkgKey]struct{}, len(keys))
// 	for _, k := range keys {
// 		set[k] = struct{}{}
// 	}
// 	return set
// }

// EnrichMetricsWithPackageImpact links package-level delta to CVE-level delta.
//
// It answers questions like:
// - how many CVEs disappeared because their packages were removed?
// - how many CVEs appeared because of newly added packages?
// - how many CVEs are on packages common to both images?
func EnrichMetricsWithPackageImpact(metrics map[string]int, deltas []vuln.DeltaRow, removedPkgs, addedPkgs, commonPkgs []bom.PkgKey) map[string]int {
	removedSet := vuln.MakePkgSet(removedPkgs)
	addedSet := vuln.MakePkgSet(addedPkgs)
	commonSet := vuln.MakePkgSet(commonPkgs)

	for _, delta := range deltas {
		// 1) CVEs that disappeared because packages were removed
		//
		// Logic:
		// - status == ONLY_UPSTREAM  → CVE does not appear in hardened
		// - r.PkgKey is in removedSet → that entire package was removed
		if _, ok := removedSet[delta.PkgKey]; ok && delta.Status == vuln.StatusOnlyUpstream {
			metrics["cves_from_removed_pkgs"]++
		}

		// 2) CVEs that appeared because of newly added packages
		//
		// Logic:
		// - status == ONLY_HARDENED → CVE only exists in hardened
		// - r.PkgKey is in addedSet → package does not exist in upstream
		if _, ok := addedSet[delta.PkgKey]; ok && delta.Status == vuln.StatusOnlyHardened {
			metrics["cves_from_added_pkgs"]++
		}

		// 3) CVEs on common packages (present in both images)
		//
		// This includes BOTH_* statuses:
		//   - BOTH_SAME_SEVERITY
		//   - BOTH_DIFF_SEVERITY
		// but we can just rely on the fact that PkgKey ∈ commonSet.
		if _, ok := commonSet[delta.PkgKey]; ok {
			metrics["cves_on_common_pkgs"]++
		}
	}

	return metrics
}
