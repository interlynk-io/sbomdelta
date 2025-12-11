package vuln

import (
	"fmt"
	"os"

	"github.com/viveksahu26/sbomdelta/pkg/types"
)

func LoadVulns(path string, format types.VulnFormat) (map[types.VulnKey]types.VulnFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading SBOM %s: %w", path, err)
	}

	switch format {
	case types.VulnFormatTrivy:
		return loadTrivy(data)
	case types.VulnFormatGrype:
		return loadGrype(data)
	default:
		return nil, fmt.Errorf("unsupported vuln format: %s", format)
	}
}
