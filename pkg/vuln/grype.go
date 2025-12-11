package vuln

import (
	"encoding/json"

	"github.com/viveksahu26/sbomdelta/pkg/types"
)

// Minimal Grype JSON structs
type grypeVuln struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
}

type grypeArtifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type grypeMatch struct {
	Vulnerability grypeVuln     `json:"vulnerability"`
	Artifact      grypeArtifact `json:"artifact"`
}

type grypeReport struct {
	Matches []grypeMatch `json:"matches"`
}

func loadGrype(data []byte) (map[types.VulnKey]types.VulnFinding, error) {
	var rep grypeReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, err
	}

	vulns := make(map[types.VulnKey]types.VulnFinding)

	for _, m := range rep.Matches {
		v := m.Vulnerability
		a := m.Artifact

		if a.Name == "" || v.ID == "" {
			continue
		}

		pkgKey := types.MakePkgKey(a.Name, a.Version)
		vulnKey := types.VulnKey{
			Pkg: pkgKey,
			CVE: v.ID,
		}

		vulns[vulnKey] = types.VulnFinding{
			Key:      vulnKey,
			Severity: types.Severity(v.Severity),
			Source:   "grype",
		}
	}
	return vulns, nil
}
