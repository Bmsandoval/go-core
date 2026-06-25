package env

import (
	"testing"
	"time"
)

func TestString(t *testing.T) {
	cases := []struct {
		name string
		set  bool
		val  string
		def  string
		want string
	}{
		{"unset -> default", false, "", "fallback", "fallback"},
		{"empty -> default", true, "", "fallback", "fallback"},
		{"set -> value", true, "hello", "fallback", "hello"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			const key = "GOCORE_ENV_TEST_STRING"
			t.Setenv(key, "") // ensure clean baseline
			if c.set {
				t.Setenv(key, c.val)
			}
			if got := String(key, c.def); got != c.want {
				t.Fatalf("String = %q, want %q", got, c.want)
			}
		})
	}
}

func TestInt(t *testing.T) {
	cases := []struct {
		name string
		val  string
		def  int
		want int
	}{
		{"unset -> default", "", 42, 42},
		{"valid", "1800", 42, 1800},
		{"negative", "-7", 42, -7},
		{"invalid -> default", "notanumber", 42, 42},
		{"float -> default", "3.14", 42, 42},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			const key = "GOCORE_ENV_TEST_INT"
			t.Setenv(key, c.val)
			if got := Int(key, c.def); got != c.want {
				t.Fatalf("Int = %d, want %d", got, c.want)
			}
		})
	}
}

func TestBool(t *testing.T) {
	cases := []struct {
		name string
		val  string
		def  bool
		want bool
	}{
		{"unset -> default true", "", true, true},
		{"unset -> default false", "", false, false},
		{"1", "1", false, true},
		{"true", "true", false, true},
		{"TRUE upper", "TRUE", false, true},
		{"yes", "yes", false, true},
		{"on padded", "  on  ", false, true},
		{"0", "0", true, false},
		{"false", "false", true, false},
		{"no", "no", true, false},
		{"off", "off", true, false},
		{"unrecognized -> default", "maybe", true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			const key = "GOCORE_ENV_TEST_BOOL"
			t.Setenv(key, c.val)
			if got := Bool(key, c.def); got != c.want {
				t.Fatalf("Bool(%q) = %v, want %v", c.val, got, c.want)
			}
		})
	}
}

func TestDuration(t *testing.T) {
	cases := []struct {
		name string
		val  string
		def  time.Duration
		want time.Duration
	}{
		{"unset -> default", "", time.Hour, time.Hour},
		{"seconds", "1800s", time.Hour, 1800 * time.Second},
		{"minutes", "30m", time.Hour, 30 * time.Minute},
		{"invalid -> default", "soon", time.Hour, time.Hour},
		{"bare number -> default", "1800", time.Hour, time.Hour},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			const key = "GOCORE_ENV_TEST_DURATION"
			t.Setenv(key, c.val)
			if got := Duration(key, c.def); got != c.want {
				t.Fatalf("Duration(%q) = %v, want %v", c.val, got, c.want)
			}
		})
	}
}

func TestCSV(t *testing.T) {
	cases := []struct {
		name string
		val  string
		want []string
	}{
		{"unset -> empty", "", []string{}},
		{"single", "a", []string{"a"}},
		{"multi trimmed", " a , b ,c ", []string{"a", "b", "c"}},
		{"empties dropped", "a,,b, ,c", []string{"a", "b", "c"}},
		{"only commas -> empty", ",, ,", []string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			const key = "GOCORE_ENV_TEST_CSV"
			t.Setenv(key, c.val)
			got := CSV(key)
			if len(got) != len(c.want) {
				t.Fatalf("CSV(%q) = %v, want %v", c.val, got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("CSV(%q)[%d] = %q, want %q", c.val, i, got[i], c.want[i])
				}
			}
		})
	}
}

func TestMustString(t *testing.T) {
	const key = "GOCORE_ENV_TEST_MUST"

	t.Run("set returns value", func(t *testing.T) {
		t.Setenv(key, "present")
		if got := MustString(key); got != "present" {
			t.Fatalf("MustString = %q, want %q", got, "present")
		}
	})

	t.Run("empty panics", func(t *testing.T) {
		t.Setenv(key, "")
		defer func() {
			if r := recover(); r == nil {
				t.Fatalf("MustString did not panic on empty value")
			}
		}()
		_ = MustString(key)
	})
}
