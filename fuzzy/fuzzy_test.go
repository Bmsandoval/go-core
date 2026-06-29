package fuzzy

import "testing"

func TestMatchBasics(t *testing.T) {
	if _, _, ok := Match("abc", "axbxc"); !ok {
		t.Errorf("expected 'abc' to match 'axbxc' as a subsequence")
	}
	if _, _, ok := Match("abc", "acb"); ok {
		t.Errorf("expected 'abc' NOT to match 'acb' (order matters)")
	}
	if s, _, ok := Match("", "anything"); !ok || s != 0 {
		t.Errorf("empty pattern should match with score 0, got ok=%v score=%d", ok, s)
	}
}

func TestMatchCaseInsensitive(t *testing.T) {
	if _, _, ok := Match("FB", "foobar"); !ok {
		t.Errorf("expected case-insensitive match")
	}
}

func TestPositions(t *testing.T) {
	_, pos, ok := Match("ac", "abc")
	if !ok {
		t.Fatal("expected match")
	}
	if len(pos) != 2 || pos[0] != 0 || pos[1] != 2 {
		t.Errorf("positions = %v, want [0 2]", pos)
	}
}

func TestScoringPrefersBoundaries(t *testing.T) {
	// "app" at a word boundary ("my application") should outscore a mid-word hit.
	boundary, _, ok1 := Match("app", "my application")
	midword, _, ok2 := Match("app", "snappy wrapper")
	if !ok1 || !ok2 {
		t.Fatalf("both should match: %v %v", ok1, ok2)
	}
	if boundary <= midword {
		t.Errorf("boundary match (%d) should outscore mid-word match (%d)", boundary, midword)
	}
}

func TestScoringPrefersConsecutive(t *testing.T) {
	consecutive, _, _ := Match("abc", "abcdef")
	scattered, _, _ := Match("abc", "axbxcx")
	if consecutive <= scattered {
		t.Errorf("consecutive (%d) should outscore scattered (%d)", consecutive, scattered)
	}
}

func TestFilterRanksAndFilters(t *testing.T) {
	items := []string{"readme.md", "main.go", "model.go", "go.mod", "nope.txt"}
	hits := Filter("go", items, func(s string) string { return s })

	if len(hits) == 0 {
		t.Fatal("expected some hits")
	}
	for _, h := range hits {
		if h.Item == "nope.txt" {
			t.Errorf("nope.txt should not match 'go'")
		}
	}
	// Results must be sorted best-first.
	for i := 1; i < len(hits); i++ {
		if hits[i-1].Score < hits[i].Score {
			t.Errorf("results not sorted best-first: %d < %d", hits[i-1].Score, hits[i].Score)
		}
	}
}

func TestFilterEmptyPatternReturnsAll(t *testing.T) {
	items := []string{"a", "b", "c"}
	hits := Filter("", items, func(s string) string { return s })
	if len(hits) != 3 {
		t.Errorf("empty pattern should return all %d items, got %d", len(items), len(hits))
	}
}
