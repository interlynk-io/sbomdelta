package sbom

import (
	"encoding/json"

	"github.com/viveksahu26/sbomdelta/pkg/types"
)

type spdxPackage struct {
	Name        string `json:"name"`
	VersionInfo string `json:"versionInfo"`
	// you can add purl later if you want: PackageURL string `json:"packageURL"`
}

type spdxDoc struct {
	Packages []spdxPackage `json:"packages"`
}

func loadSPDX(data []byte) (map[types.PkgKey]types.Package, error) {
	var doc spdxDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}

	pkgs := make(map[types.PkgKey]types.Package)
	for _, p := range doc.Packages {
		if p.Name == "" {
			continue
		}
		key := types.MakePkgKey(p.Name, p.VersionInfo)
		pkgs[key] = types.Package{
			Name:    p.Name,
			Version: p.VersionInfo,
		}
	}
	return pkgs, nil
}
