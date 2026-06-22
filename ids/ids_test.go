package ids

import (
	"strings"
	"testing"
	"time"
)

func TestNewULIDLengthAndSortable(t *testing.T) {
	a, err := NewULID()
	if err != nil {
		t.Fatalf("NewULID: %v", err)
	}
	if len(a) != 26 {
		t.Fatalf("ULID length = %d, want 26 (%q)", len(a), a)
	}
	time.Sleep(2 * time.Millisecond)
	b, err := NewULID()
	if err != nil {
		t.Fatalf("NewULID: %v", err)
	}
	if !(a < b) {
		t.Fatalf("ULIDs not lexicographically sortable by time: %q !< %q", a, b)
	}
}

func TestPrefixed(t *testing.T) {
	got, err := Prefixed("flag")
	if err != nil {
		t.Fatalf("Prefixed: %v", err)
	}
	if !strings.HasPrefix(got, "flag_") {
		t.Fatalf("Prefixed = %q, want flag_ prefix", got)
	}
	if _, err := Prefixed(""); err == nil {
		t.Fatal("Prefixed(\"\") should error on empty prefix")
	}
}
