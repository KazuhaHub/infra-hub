package httpsapi

import (
	"sync"
	"time"
)

// limiter is a set of token buckets keyed by string (a host name or a peer address). The key set is bounded: when it
// is full, idle buckets are dropped first, and a full table of busy keys refuses new ones rather than growing.
type limiter struct {
	mu      sync.Mutex
	rate    float64 // tokens per second
	burst   float64
	max     int
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(perMinute, burst, maxKeys int) *limiter {
	return &limiter{rate: float64(perMinute) / 60, burst: float64(burst), max: maxKeys, buckets: map[string]*bucket{}}
}

func (l *limiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.buckets[key]
	if b == nil {
		if len(l.buckets) >= l.max {
			l.sweep(now)
			if len(l.buckets) >= l.max {
				return false
			}
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	if d := now.Sub(b.last).Seconds(); d > 0 {
		b.tokens = min(l.burst, b.tokens+d*l.rate)
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweep drops buckets that have refilled completely: forgetting them changes nothing.
func (l *limiter) sweep(now time.Time) {
	for k, b := range l.buckets {
		if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
			delete(l.buckets, k)
		}
	}
}
