package delta

import (
	"reflect"
	"sort"
	"testing"

	"github.com/viveksahu26/sbomdelta/pkg/types"
)

// helper to sort []PkgKey for stable comparisons
func sortKeys(keys []types.PkgKey) {
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})
}

func TestComputePackageDelta_Basic(t *testing.T) {
	// upstream: A, B
	upstreamPkgs := map[types.PkgKey]types.Package{
		types.MakePkgKey("curl", "7.80.0"): {Name: "curl", Version: "7.80.0"},
		types.MakePkgKey("bash", "5.1"):    {Name: "bash", Version: "5.1"},
	}

	// hardened: B, C
	hardenedPkgs := map[types.PkgKey]types.Package{
		types.MakePkgKey("bash", "5.1"):     {Name: "bash", Version: "5.1"},
		types.MakePkgKey("busybox", "1.36"): {Name: "busybox", Version: "1.36"},
	}

	removed, added, common := ComputePackageDelta(upstreamPkgs, hardenedPkgs)
	// sort slices to make order deterministic for comparison
	sortKeys(removed)
	sortKeys(added)
	sortKeys(common)

	wantRemoved := []types.PkgKey{
		types.MakePkgKey("curl", "7.80.0"),
	}
	wantAdded := []types.PkgKey{
		types.MakePkgKey("busybox", "1.36"),
	}
	wantCommon := []types.PkgKey{
		types.MakePkgKey("bash", "5.1"),
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
	upstreamPkgs := map[types.PkgKey]types.Package{
		types.MakePkgKey("curl", "7.80.0"): {Name: "curl", Version: "7.80.0"},
		types.MakePkgKey("bash", "5.1"):    {Name: "bash", Version: "5.1"},
	}

	hardenedPkgs := map[types.PkgKey]types.Package{
		types.MakePkgKey("curl", "7.80.0"): {Name: "curl", Version: "7.80.0"},
		types.MakePkgKey("bash", "5.1"):    {Name: "bash", Version: "5.1"},
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

	wantCommon := []types.PkgKey{
		types.MakePkgKey("bash", "5.1"),
		types.MakePkgKey("curl", "7.80.0"),
	}
	if !reflect.DeepEqual(common, wantCommon) {
		t.Errorf("common mismatch:\n  got:  %#v\n  want: %#v", common, wantCommon)
	}
}
