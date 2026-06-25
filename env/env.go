// Package env provides a tiny, dependency-free reader for environment
// variables with typed lookups and fallbacks. It mirrors the getEnv/getEnvInt/
// getEnvBool/splitCSV helpers that the Go starters previously duplicated in each
// configs package, so a starter's Load() can read its config from one place.
//
// An environment variable is treated as "unset" when os.Getenv returns the
// empty string; in that case the provided default is returned. Malformed values
// (e.g. a non-numeric Int) also fall back to the default rather than erroring.
package env

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// String returns the value of key, or def when key is unset or empty.
func String(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// Int returns the value of key parsed as a base-10 integer, or def when key is
// unset, empty, or not a valid integer.
func Int(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

// Bool returns the value of key interpreted as a boolean, or def when key is
// unset, empty, or not a recognized truthy/falsey token. Recognized (case- and
// space-insensitive) true values are "1", "true", "yes", "on"; false values are
// "0", "false", "no", "off".
func Bool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "1", "true", "yes", "on":
			return true
		case "0", "false", "no", "off":
			return false
		}
	}
	return def
}

// Duration returns the value of key parsed with time.ParseDuration (e.g.
// "1800s", "30m", "24h"), or def when key is unset, empty, or not a valid
// duration.
func Duration(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}

// CSV splits the value of key on commas, trims surrounding whitespace from each
// element, and drops empty elements. It returns an empty (non-nil) slice when
// key is unset or contains no non-empty elements.
func CSV(key string) []string {
	raw := os.Getenv(key)
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// MustString returns the value of key, or panics when key is unset or empty.
// Use it for required configuration that has no safe default.
func MustString(key string) string {
	v := os.Getenv(key)
	if v == "" {
		panic("env: required environment variable " + key + " is unset or empty")
	}
	return v
}
