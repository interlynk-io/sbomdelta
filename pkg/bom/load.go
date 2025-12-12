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

package bom

import (
	"context"
	"fmt"
	"os"

	"github.com/interlynk-io/sbomqs/v2/pkg/sbom"
)

// PkgKey is the normalized key we use for package identity.
type PkgKey string

// Package is a minimal view we care about for delta.
type Package struct {
	Name    string
	Version string
	Purl    string
}

// MakePkgKey creates package key with a combination of package name "@" package version
// and returns it
func MakePkgKey(name, version string) PkgKey {
	if version == "" {
		return PkgKey(name)
	}
	return PkgKey(name + "@" + version)
}

func NewLoadSBOM(path string) (map[PkgKey]Package, error) {
	var f *os.File

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file for reading: %q: %w", path, err)
	}

	ctx := context.Background()
	doc, err := sbom.NewSBOMDocument(ctx, f, sbom.Signature{})
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("parse error for %q: %w", path, err)
	}

	return load(doc)
}

func load(doc sbom.Document) (map[PkgKey]Package, error) {
	pkgs := make(map[PkgKey]Package)
	for _, c := range doc.Components() {
		if c.GetName() == "" {
			continue
		}

		key := MakePkgKey(c.GetName(), c.GetVersion())
		pkgs[key] = Package{
			Name:    c.GetName(),
			Version: c.GetVersion(),
			Purl:    getPurl(c),
		}
	}
	return pkgs, nil
}

func getPurl(c sbom.GetComponent) string {
	for _, p := range c.GetPurls() {
		return p.String()
	}

	return ""
}
