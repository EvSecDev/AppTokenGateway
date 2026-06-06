package main

import (
	"time"
)

func newLogLimiter(maxLogs int64, interval time.Duration) (newLimiter *logLimiter) {
	newLimiter = &logLimiter{
		interval: interval,
	}
	newLimiter.maxLogs.Store(maxLogs)
	newLimiter.resetAt.Store(time.Now().Add(interval).UnixNano())
	return
}

func (limiter *logLimiter) Allow() (logPermitted bool) {
	now := time.Now().UnixNano()

	// reset if window expired
	resetAt := limiter.resetAt.Load()
	if now > resetAt {
		success := limiter.resetAt.CompareAndSwap(resetAt, time.Now().Add(limiter.interval).UnixNano())
		if success {
			limiter.count.Store(0)
		}
	}

	// increment and check
	newCount := limiter.count.Add(1)
	if newCount <= limiter.maxLogs.Load() {
		logPermitted = true
		return
	}
	return
}
