package types

import (
	"fmt"
)

// SBOMFormat represents the logical SBOM schema (not file extension).
type SBOMFormat string

const (
	SBOMFormatCycloneDX SBOMFormat = "cyclonedx"
	SBOMFormatSPDX      SBOMFormat = "spdx"
)

type VulnFormat string

const (
	VulnFormatTrivy VulnFormat = "trivy"
	VulnFormatGrype VulnFormat = "grype"
)

func ParseSBOMFormat(s string) (SBOMFormat, error) {
	switch s {
	case "cyclonedx", "cdx":
		return SBOMFormatCycloneDX, nil
	case "spdx":
		return SBOMFormatSPDX, nil
	default:
		return "", fmt.Errorf("unsupported SBOM format %q (expected cyclonedx or spdx)", s)
	}
}

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

// Config holds all user inputs for a single delta evaluation run.
type Config struct {
	UpstreamSBOMPath   string
	UpstreamSBOMFormat SBOMFormat

	HardenedSBOMPath   string
	HardenedSBOMFormat SBOMFormat

	UpstreamVulnPath   string
	UpstreamVulnFormat VulnFormat

	HardenedVulnPath   string
	HardenedVulnFormat VulnFormat

	BackportVulnPath   string
	BackportVulnFormat VulnFormat
}

// PkgKey is the normalized key we use for package identity.
type PkgKey string

// Package is a minimal view we care about for delta.
type Package struct {
	Name    string
	Version string
	Purl    string
}

func MakePkgKey(name, version string) PkgKey {
	if version == "" {
		return PkgKey(name)
	}
	return PkgKey(name + "@" + version)
}

// VulnKey: “which package, which CVE”.
type VulnKey struct {
	Pkg PkgKey
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

func MakeVulnKey(pkgKey PkgKey, cve string) VulnKey {
	return VulnKey{
		Pkg: pkgKey,
		CVE: cve,
	}
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
	PkgKey           PkgKey
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

func MakePkgSet(keys []PkgKey) map[PkgKey]struct{} {
	set := make(map[PkgKey]struct{}, len(keys))
	for _, k := range keys {
		set[k] = struct{}{}
	}
	return set
}
