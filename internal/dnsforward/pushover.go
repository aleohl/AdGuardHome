package dnsforward

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/golibs/logutil/slogutil"
)

// pushoverAPIURL is the Pushover API endpoint for sending messages.
const pushoverAPIURL = "https://api.pushover.net/1/messages.json"

// PushoverConfig contains Pushover notification settings.
type PushoverConfig struct {
	// AppToken is the Pushover application API token.
	AppToken string

	// UserKey is the Pushover user/group key.
	UserKey string

	// Sound is the optional notification sound.
	Sound string

	// RateLimitPer5Min is the maximum notifications per domain per 5 minutes.
	RateLimitPer5Min int

	// GlobalRateLimitPerMin is the maximum notifications per minute globally.
	GlobalRateLimitPerMin int

	// Priority is the Pushover message priority (-2 to 2).
	Priority int
}

// PushoverNotifier sends notifications via Pushover.
type PushoverNotifier struct {
	logger          *slog.Logger
	client          *http.Client
	domainRateLimit *domainRateLimit
	globalRateLimit *globalRateLimit
	config          *PushoverConfig
}

// NewPushoverNotifier creates a new Pushover notifier.
func NewPushoverNotifier(logger *slog.Logger, config *PushoverConfig) *PushoverNotifier {
	return &PushoverNotifier{
		logger: logger,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		config:          config,
		domainRateLimit: newDomainRateLimit(config.RateLimitPer5Min),
		globalRateLimit: newGlobalRateLimit(config.GlobalRateLimitPerMin),
	}
}

// NotificationEvent represents a custom rule match event.
type NotificationEvent struct {
	// Domain is the matched domain name.
	Domain string

	// RuleText is the text of the matched rule.
	RuleText string

	// ClientIP is the IP address of the client that made the request.
	ClientIP string

	// ClientID is the client identifier (if available).
	ClientID string

	// Reason is the filtering reason.
	Reason filtering.Reason

	// Timestamp is when the event occurred.
	Timestamp time.Time
}

// ShouldNotify checks if a notification should be sent for this domain.
// It checks both global and per-domain rate limits.
func (n *PushoverNotifier) ShouldNotify(domain string) (ok bool, reason string) {
	// Check global rate limit first.
	if !n.globalRateLimit.shouldNotify() {
		return false, "global"
	}

	// Check per-domain rate limit.
	if !n.domainRateLimit.shouldNotify(domain) {
		return false, "domain"
	}

	return true, ""
}

// SendAsync sends a notification asynchronously.
func (n *PushoverNotifier) SendAsync(ctx context.Context, event *NotificationEvent) {
	go func() {
		if err := n.send(ctx, event); err != nil {
			n.logger.ErrorContext(ctx, "sending pushover notification",
				slogutil.KeyError, err,
				"domain", event.Domain,
			)
		}
	}()
}

// send performs the actual HTTP request to Pushover.
func (n *PushoverNotifier) send(ctx context.Context, event *NotificationEvent) error {
	title := n.formatTitle(event.Reason)
	message := n.formatMessage(event)

	data := url.Values{
		"token":   {n.config.AppToken},
		"user":    {n.config.UserKey},
		"title":   {title},
		"message": {message},
	}

	if n.config.Priority != 0 {
		data.Set("priority", fmt.Sprintf("%d", n.config.Priority))
	}
	if n.config.Sound != "" {
		data.Set("sound", n.config.Sound)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		pushoverAPIURL, bytes.NewBufferString(data.Encode()))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pushover returned status %d", resp.StatusCode)
	}

	n.logger.DebugContext(ctx, "pushover notification sent",
		"domain", event.Domain,
		"reason", event.Reason.String(),
	)

	return nil
}

// formatTitle creates the notification title based on the reason.
func (n *PushoverNotifier) formatTitle(reason filtering.Reason) string {
	switch reason {
	case filtering.FilteredBlockList:
		return "AdGuard: Domain Blocked"
	case filtering.NotFilteredAllowList:
		return "AdGuard: Domain Allowed"
	case filtering.Rewritten, filtering.RewrittenRule:
		return "AdGuard: Domain Rewritten"
	default:
		return "AdGuard: Custom Rule Match"
	}
}

// formatMessage creates the notification body.
func (n *PushoverNotifier) formatMessage(event *NotificationEvent) string {
	clientInfo := event.ClientIP
	if event.ClientID != "" {
		clientInfo = fmt.Sprintf("%s (%s)", event.ClientID, event.ClientIP)
	}

	return fmt.Sprintf("Domain: %s\nClient: %s\nTime: %s",
		event.Domain,
		clientInfo,
		event.Timestamp.Format(time.RFC3339),
	)
}

// Cleanup removes old rate limit entries.
func (n *PushoverNotifier) Cleanup() {
	n.domainRateLimit.cleanup()
}
