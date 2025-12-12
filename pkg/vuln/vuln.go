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

package vuln

import (
	"fmt"
	"os"

	"github.com/interlynk-io/sbomdelta/pkg/bom"
)

// VulnKey: “which package, which CVE”.
type VulnKey struct {
	Pkg bom.PkgKey
	CVE string
}

// Severity is normalized severity (HIGH, CRITICAL, etc.).
type Severity string

// VulnFinding is one row from a scanner report.
type VulnFinding struct {
	Key      VulnKey
	Severity Severity
	Source   string // "trivy" / "grype" / etc. (optional but nice)
}

// Status for delta rows
type DeltaStatus string

const (
	StatusOnlyUpstream     DeltaStatus = "ONLY_UPSTREAM"
	StatusOnlyHardened     DeltaStatus = "ONLY_HARDENED"
	StatusBothSameSeverity DeltaStatus = "BOTH_SAME_SEVERITY"
	StatusBothDiffSeverity DeltaStatus = "BOTH_DIFF_SEVERITY"
)

type DeltaRow struct {
	PkgKey           bom.PkgKey
	CVE              string
	Status           DeltaStatus
	SeverityUp       Severity
	SeverityHardened Severity
}

const (
	SeverityUnknown  Severity = "UNKNOWN"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

type VulnFormat string

const (
	VulnFormatTrivy VulnFormat = "trivy"
	VulnFormatGrype VulnFormat = "grype"
)

func ParseVulnFormat(s string) (VulnFormat, error) {
	switch s {
	case "trivy":
		return VulnFormatTrivy, nil
	case "grype":
		return VulnFormatGrype, nil
	default:
		return "", fmt.Errorf("unsupported vuln format %q (expected trivy or grype)", s)
	}
}

func MakePkgSet(keys []bom.PkgKey) map[bom.PkgKey]struct{} {
	set := make(map[bom.PkgKey]struct{}, len(keys))
	for _, k := range keys {
		set[k] = struct{}{}
	}
	return set
}

func MakeVulnKey(pkgKey bom.PkgKey, cve string) VulnKey {
	return VulnKey{
		Pkg: pkgKey,
		CVE: cve,
	}
}

func LoadVulns(path string, format VulnFormat) (map[VulnKey]VulnFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading SBOM %s: %w", path, err)
	}

	switch format {
	case VulnFormatTrivy:
		return loadTrivy(data)
	case VulnFormatGrype:
		return loadGrype(data)
	default:
		return nil, fmt.Errorf("unsupported vuln format: %s", format)
	}
}
