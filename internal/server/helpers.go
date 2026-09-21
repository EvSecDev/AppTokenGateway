package server

import (
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
)

var clientAddr func(request *http.Request) (remote string) = func(request *http.Request) (remote string) {
	// Base initialized version of client addr retrieval.
	return request.RemoteAddr
}

// Retrieves the actual client address if set in forwarded for header (from a configured trusted proxy).
// Otherwise falls back to the direct source address.
func setClientAddressRetriever(trustedProxies []string) {
	clientAddr = func(request *http.Request) (remote string) {
		forwardedFor := request.Header.Get("X-Forwarded-For")

		networkSource := extractRemoteAddressIP(request.RemoteAddr)

		// Only using forwarded for when actual remote is a trusted proxy
		if forwardedFor != "" && slices.Contains(trustedProxies, networkSource) {
			fields := strings.Split(forwardedFor, ",")

			if len(fields) > 0 {
				// First entry is the originating client
				remote = strings.TrimSpace(fields[0])
				if remote != "" {
					if net.ParseIP(remote) != nil {
						return
					}
				}
			}
		}

		// Fall back to the direct request (raw) source address
		remote = request.RemoteAddr
		return
	}
	return
}

// Attempts to extract a sole IP address from a raw request address.
// If extraction is unsuccessful, this returns an empty string.
func extractRemoteAddressIP(rawAddress string) (ip string) {
	host, _, err := net.SplitHostPort(rawAddress)
	if err != nil {
		return
	}

	parsedIP, err := netip.ParseAddr(host)
	if err != nil {
		return
	}
	ip = parsedIP.String()
	return
}
