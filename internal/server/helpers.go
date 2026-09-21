package server

import (
	"net"
	"net/http"
	"strings"
)

// Retrieves the actual client address if set in forwarded for header.
// Otherwise falls back to the direct source address.
func clientAddr(request *http.Request) (remote string) {
	forwardedFor := request.Header.Get("X-Forwarded-For")
	if forwardedFor != "" {
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
	// Fall back to the direct request source address
	remote = request.RemoteAddr
	return
}
