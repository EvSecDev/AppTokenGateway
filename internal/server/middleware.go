package server

import (
	"net/http"

	"golang.org/x/time/rate"
)

const (
	// Maximum allowed request body size (bytes).
	// Registration/revocation payloads are small JSON documents, so a few KiB is far more than enough.
	MaxBodySize int64 = 4 << 10 // 4 KiB

	// Maximum /callback requests per second.
	MaxCallbackRequestsPerSecond int64 = 10
)

// Middleware that caps the request body at maxBytes.
// When the limit is exceeded, http.MaxBytesReader errors on further reads and closes the connection.
func LimitBodySize(maxBytes int64) (sizeLimiter func(http.Handler) http.Handler) {
	sizeLimiter = func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if request.Body != nil {
				request.Body = http.MaxBytesReader(response, request.Body, maxBytes)
			}
			next.ServeHTTP(response, request)
		})
	}
	return
}

// Middleware that allows at most the limiter's rate of requests.
// Excess requests receive 429 Too Many Requests.
// This is a process-wide limiter (no per-client storage).
func LimitRequests(limiter *rate.Limiter) (reqLimiter func(http.Handler) http.Handler) {
	reqLimiter = func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			if !limiter.Allow() {
				http.Error(response, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(response, request)
		})
	}
	return
}
