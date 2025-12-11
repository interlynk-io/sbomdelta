package vuln

import (
	"encoding/json"

	"github.com/viveksahu26/sbomdelta/pkg/types"
)

// Minimal Trivy JSON structs
type trivyVuln struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	Severity         string `json:"Severity"`
}

type trivyResult struct {
	Vulnerabilities []trivyVuln `json:"Vulnerabilities"`
}

type trivyReport struct {
	Results []trivyResult `json:"Results"`
}

func loadTrivy(data []byte) (map[types.VulnKey]types.VulnFinding, error) {
	var rep trivyReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, err
	}

	vulns := make(map[types.VulnKey]types.VulnFinding)

	for _, r := range rep.Results {
		for _, v := range r.Vulnerabilities {
			if v.PkgName == "" || v.VulnerabilityID == "" {
				continue
			}
			pkgKey := types.MakePkgKey(v.PkgName, v.InstalledVersion)
			vulnKey := types.VulnKey{
				Pkg: pkgKey,
				CVE: v.VulnerabilityID,
			}

			vulns[vulnKey] = types.VulnFinding{
				Key:      vulnKey,
				Severity: types.Severity(v.Severity),
				Source:   "trivy",
			}
		}
	}
	return vulns, nil
}
