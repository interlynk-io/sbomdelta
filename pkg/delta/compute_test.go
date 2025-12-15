// Copyright 2025 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package delta

import (
	"reflect"
	"sort"
	"testing"

	"github.com/interlynk-io/sbomdelta/pkg/bom"
)

// helper to sort []PkgKey for stable comparisons
func sortKeys(keys []bom.PkgKey) {
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})
}

func TestComputePackageDelta_Basic(t *testing.T) {
	// upstream: A, B
	upstreamPkgs := map[bom.PkgKey]bom.Package{
		bom.MakePkgKey("curl", "7.80.0"): {Name: "curl", Version: "7.80.0"},
		bom.MakePkgKey("bash", "5.1"):    {Name: "bash", Version: "5.1"},
	}

	// hardened: B, C
	hardenedPkgs := map[bom.PkgKey]bom.Package{
		bom.MakePkgKey("bash", "5.1"):     {Name: "bash", Version: "5.1"},
		bom.MakePkgKey("busybox", "1.36"): {Name: "busybox", Version: "1.36"},
	}

	removed, added, common := ComputePackageDelta(upstreamPkgs, hardenedPkgs)
	// sort slices to make order deterministic for comparison
	sortKeys(removed)
	sortKeys(added)
	sortKeys(common)

	wantRemoved := []bom.PkgKey{
		bom.MakePkgKey("curl", "7.80.0"),
	}
	wantAdded := []bom.PkgKey{
		bom.MakePkgKey("busybox", "1.36"),
	}
	wantCommon := []bom.PkgKey{
		bom.MakePkgKey("bash", "5.1"),
	}

	if !reflect.DeepEqual(removed, wantRemoved) {
		t.Errorf("removed mismatch:\n  got:  %#v\n  want: %#v", removed, wantRemoved)
	}
	if !reflect.DeepEqual(added, wantAdded) {
		t.Errorf("added mismatch:\n  got:  %#v\n  want: %#v", added, wantAdded)
	}
	if !reflect.DeepEqual(common, wantCommon) {
		t.Errorf("common mismatch:\n  got:  %#v\n  want: %#v", common, wantCommon)
	}
}

func TestComputePackageDelta_IdenticalSets(t *testing.T) {
	upstreamPkgs := map[bom.PkgKey]bom.Package{
		bom.MakePkgKey("curl", "7.80.0"): {Name: "curl", Version: "7.80.0"},
		bom.MakePkgKey("bash", "5.1"):    {Name: "bash", Version: "5.1"},
	}

	hardenedPkgs := map[bom.PkgKey]bom.Package{
		bom.MakePkgKey("curl", "7.80.0"): {Name: "curl", Version: "7.80.0"},
		bom.MakePkgKey("bash", "5.1"):    {Name: "bash", Version: "5.1"},
	}

	removed, added, common := ComputePackageDelta(upstreamPkgs, hardenedPkgs)

	sortKeys(removed)
	sortKeys(added)
	sortKeys(common)

	if len(removed) != 0 {
		t.Errorf("expected no removed packages, got: %#v", removed)
	}
	if len(added) != 0 {
		t.Errorf("expected no added packages, got: %#v", added)
	}

	wantCommon := []bom.PkgKey{
		bom.MakePkgKey("bash", "5.1"),
		bom.MakePkgKey("curl", "7.80.0"),
	}
	if !reflect.DeepEqual(common, wantCommon) {
		t.Errorf("common mismatch:\n  got:  %#v\n  want: %#v", common, wantCommon)
	}
}
