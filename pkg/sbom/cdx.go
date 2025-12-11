package sbom

import (
	"encoding/json"

	"github.com/viveksahu26/sbomdelta/pkg/types"
)

type cdxComponent struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Purl    string `json:"purl"`
}

type cdxBOM struct {
	Components []cdxComponent `json:"components"`
}

func loadCycloneDX(data []byte) (map[types.PkgKey]types.Package, error) {
	var bom cdxBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, err
	}

	pkgs := make(map[types.PkgKey]types.Package)
	for _, c := range bom.Components {
		if c.Name == "" {
			continue
		}
		key := types.MakePkgKey(c.Name, c.Version)
		pkgs[key] = types.Package{
			Name:    c.Name,
			Version: c.Version,
			Purl:    c.Purl,
		}
	}
	return pkgs, nil
}
