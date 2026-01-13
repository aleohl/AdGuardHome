package dnsforward

import (
	"context"
	"sync"
	"time"
)

// domainRateLimit tracks notification rate limits per domain.
type domainRateLimit struct {
	mu           sync.RWMutex
	lastNotified map[string]time.Time
	interval     time.Duration
}

// newDomainRateLimit creates a new rate limiter with a 5-minute base interval.
func newDomainRateLimit(perFiveMinutes int) *domainRateLimit {
	interval := 5 * time.Minute
	if perFiveMinutes > 1 {
		interval = 5 * time.Minute / time.Duration(perFiveMinutes)
	}
	return &domainRateLimit{
		lastNotified: make(map[string]time.Time),
		interval:     interval,
	}
}

// shouldNotify returns true if a notification should be sent for the domain.
// It also updates the last notification time if true.
func (r *domainRateLimit) shouldNotify(domain string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	if last, ok := r.lastNotified[domain]; ok {
		if now.Sub(last) < r.interval {
			return false
		}
	}

	r.lastNotified[domain] = now
	return true
}

// cleanup removes old entries to prevent memory growth.
func (r *domainRateLimit) cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()

	cutoff := time.Now().Add(-r.interval * 2)
	for domain, t := range r.lastNotified {
		if t.Before(cutoff) {
			delete(r.lastNotified, domain)
		}
	}
}

// processNotifications sends notifications for rule matches.
func (s *Server) processNotifications(ctx context.Context, dctx *dnsContext, host string) {
	result := dctx.result
	if result == nil || len(result.Rules) == 0 {
		return
	}

	// Use the first matched rule for the notification.
	rule := result.Rules[0]

	// Check rate limit before sending.
	if !s.notifier.ShouldNotify(host) {
		s.logger.DebugContext(ctx, "notification rate limited", "domain", host)
		return
	}

	event := &NotificationEvent{
		Domain:    host,
		RuleText:  rule.Text,
		Reason:    result.Reason,
		ClientIP:  dctx.proxyCtx.Addr.Addr().String(),
		ClientID:  dctx.clientID,
		Timestamp: time.Now(),
	}

	s.logger.DebugContext(ctx, "sending pushover notification",
		"domain", host,
		"rule", rule.Text,
		"reason", result.Reason,
	)

	s.notifier.SendAsync(ctx, event)
}
