// Package ratelimit provides a per-client-IP token bucket limiter and
// trusted-proxy aware client IP extraction.
package ratelimit

import (
	"math"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type entry struct {
	lim  *rate.Limiter
	seen time.Time
}

// Limiter is a per-key token bucket set with idle eviction.
type Limiter struct {
	mu      sync.Mutex
	buckets map[netip.Addr]*entry
	rate    rate.Limit
	burst   int
	idle    time.Duration
	now     func() time.Time
}

// New creates a limiter allowing rpm requests per minute with the given burst.
func New(rpm float64, burst int) *Limiter {
	return &Limiter{
		buckets: map[netip.Addr]*entry{},
		rate:    rate.Limit(rpm / 60.0),
		burst:   burst,
		idle:    10 * time.Minute,
		now:     time.Now,
	}
}

// AllowN consumes n tokens for key; if not allowed it returns the suggested
// wait before retrying. n is clamped to the burst size. When allowed, undo
// returns the tokens, for a request that is refused later on.
func (l *Limiter) AllowN(key netip.Addr, n int) (ok bool, wait time.Duration, undo func()) {
	now := l.now()
	r := l.bucket(key, now).ReserveN(now, l.clamp(n))
	if !r.OK() {
		return false, time.Minute, func() {}
	}
	if d := r.DelayFrom(now); d > 0 {
		r.CancelAt(now)
		return false, d, func() {}
	}
	return true, 0, func() { r.CancelAt(l.now()) }
}

// Wait returns how long until n tokens are available for key, without
// consuming any.
func (l *Limiter) Wait(key netip.Addr, n int) time.Duration {
	now := l.now()
	r := l.bucket(key, now).ReserveN(now, l.clamp(n))
	if !r.OK() {
		return time.Minute
	}
	defer r.CancelAt(now)
	return r.DelayFrom(now)
}

func (l *Limiter) clamp(n int) int {
	return min(max(n, 1), l.burst)
}

func (l *Limiter) bucket(key netip.Addr, now time.Time) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.buckets[key]
	if !ok {
		e = &entry{lim: rate.NewLimiter(l.rate, l.burst)}
		l.buckets[key] = e
	}
	e.seen = now
	return e.lim
}

// Sweep removes buckets idle longer than the idle window.
func (l *Limiter) Sweep() {
	cut := l.now().Add(-l.idle)
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, e := range l.buckets {
		if e.seen.Before(cut) {
			delete(l.buckets, k)
		}
	}
}

// RunSweeper sweeps periodically until stop is closed.
func (l *Limiter) RunSweeper(stop <-chan struct{}) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			l.Sweep()
		case <-stop:
			return
		}
	}
}

// RetryAfterSeconds rounds a wait up to whole seconds (min 1).
func RetryAfterSeconds(d time.Duration) int {
	s := int(math.Ceil(d.Seconds()))
	if s < 1 {
		s = 1
	}
	return s
}

// ClientIP returns the real client address. If the direct peer is a trusted
// proxy and header is set (e.g. CF-Connecting-IP) and holds a valid IP, that
// IP is used. Otherwise X-Forwarded-For is walked right-to-left and the first
// hop that is not itself a trusted proxy is returned.
func ClientIP(r *http.Request, trusted []netip.Prefix, header string) netip.Addr {
	peer := parseAddr(r.RemoteAddr)
	if !isTrusted(peer, trusted) {
		return peer
	}
	if header != "" {
		if a := parseAddr(r.Header.Get(header)); a.IsValid() {
			return a
		}
	}
	var hops []string
	for _, h := range r.Header.Values("X-Forwarded-For") {
		for _, p := range strings.Split(h, ",") {
			if p = strings.TrimSpace(p); p != "" {
				hops = append(hops, p)
			}
		}
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a := parseAddr(hops[i])
		if !a.IsValid() {
			// Garbage in a hop we can't verify: stop and use the last good one.
			break
		}
		if !isTrusted(a, trusted) {
			return a
		}
		peer = a
	}
	return peer
}

func isTrusted(a netip.Addr, trusted []netip.Prefix) bool {
	if !a.IsValid() {
		return false
	}
	for _, p := range trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func parseAddr(s string) netip.Addr {
	s = strings.TrimSpace(s)
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	s = strings.Trim(s, "[]")
	if i := strings.IndexByte(s, '%'); i >= 0 { // zone
		s = s[:i]
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}
