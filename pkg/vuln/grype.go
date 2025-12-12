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
	"encoding/json"

	"github.com/interlynk-io/sbomdelta/pkg/bom"
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

func loadGrype(data []byte) (map[VulnKey]VulnFinding, error) {
	var rep grypeReport
	if err := json.Unmarshal(data, &rep); err != nil {
		return nil, err
	}

	vulns := make(map[VulnKey]VulnFinding)

	for _, m := range rep.Matches {
		v := m.Vulnerability
		a := m.Artifact

		if a.Name == "" || v.ID == "" {
			continue
		}

		pkgKey := bom.MakePkgKey(a.Name, a.Version)
		vulnKey := VulnKey{
			Pkg: pkgKey,
			CVE: v.ID,
		}

		vulns[vulnKey] = VulnFinding{
			Key:      vulnKey,
			Severity: Severity(v.Severity),
			Source:   "grype",
		}
	}
	return vulns, nil
}
