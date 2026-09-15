package logger

import (
	"sync/atomic"
	"time"
)

var (
	Limit *Limiter
)

const (
	MaxLogsPerSecond int64 = 2
)

func init() {
	// Default
	Limit = NewLimiter(MaxLogsPerSecond, time.Second)
}

type Limiter struct {
	interval time.Duration
	maxLogs  atomic.Int64
	count    atomic.Int64
	resetAt  atomic.Int64 // unix nano
}

func NewLimiter(maxLogs int64, interval time.Duration) (newLimiter *Limiter) {
	newLimiter = &Limiter{
		interval: interval,
	}
	newLimiter.maxLogs.Store(maxLogs)
	newLimiter.resetAt.Store(time.Now().Add(interval).UnixNano())
	return
}

func (limiter *Limiter) Allow() (logPermitted bool) {
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
