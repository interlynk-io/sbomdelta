package sbom

import (
	"fmt"
	"os"

	"github.com/viveksahu26/sbomdelta/pkg/types"
)

func LoadSBOM(path string, format types.SBOMFormat) (map[types.PkgKey]types.Package, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading SBOM %s: %w", path, err)
	}

	switch format {
	case types.SBOMFormatCycloneDX:
		return loadCycloneDX(data)
	case types.SBOMFormatSPDX:
		return loadSPDX(data)
	default:
		return nil, fmt.Errorf("unsupported SBOM format: %s", format)
	}
}
