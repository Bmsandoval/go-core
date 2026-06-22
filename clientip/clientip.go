// Package clientip extracts a best-effort client IP address from an HTTP
// request. It consolidates the three near-identical copies that previously
// lived in rate-limiting, auth, and logging middleware.
package clientip

import (
	"net"
	"net/http"
	"strings"
)

// FromRequest returns the best-effort client IP for r.
//
// Precedence:
//  1. The first address in X-Forwarded-For (the original client when behind a
//     trusted proxy / load balancer).
//  2. X-Real-IP.
//  3. The connection's RemoteAddr (host portion).
//
// NOTE: X-Forwarded-For and X-Real-IP are client-controllable. Only trust them
// when the service sits behind a proxy that overwrites them (ALB, CloudFront,
// nginx). For directly-exposed services, prefer RemoteAddrOnly.
func FromRequest(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// "client, proxy1, proxy2" — the left-most entry is the origin client.
		if first, _, ok := strings.Cut(xff, ","); ok {
			if ip := normalize(first); ip != "" {
				return ip
			}
		} else if ip := normalize(xff); ip != "" {
			return ip
		}
	}
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		if ip := normalize(xrip); ip != "" {
			return ip
		}
	}
	return RemoteAddrOnly(r)
}

// RemoteAddrOnly returns the host portion of r.RemoteAddr, ignoring any
// proxy headers. Use this when the service is directly exposed and forwarded
// headers cannot be trusted.
func RemoteAddrOnly(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		// RemoteAddr may already be a bare host (e.g. in tests).
		return normalize(r.RemoteAddr)
	}
	return normalize(host)
}

// normalize trims whitespace and validates that s parses as an IP, returning
// the canonical form or "" if it is not a valid address.
func normalize(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return ""
}
