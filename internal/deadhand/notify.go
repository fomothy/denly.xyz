package deadhand

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"time"
)

// Escalation delivery.
//
// Two transports, both chosen because they need no long-lived connection and
// no extra dependency: SMTP from the standard library, and an outbound
// webhook. Nostr DM would need a relay client — websockets, subscription
// management, reconnection — which is a large dependency for one feature, so
// it is deliberately not here. The Notifier interface is where it would go.

// MultiNotifier dispatches to whichever transport a contact names.
type MultiNotifier struct {
	Email   Notifier
	Webhook Notifier
}

// Notify routes by contact kind.
func (m MultiNotifier) Notify(ctx context.Context, c Contact, subject, body string) error {
	switch c.Kind {
	case ContactEmail:
		if m.Email == nil {
			return errors.New("deadhand: email escalation is not configured")
		}
		return m.Email.Notify(ctx, c, subject, body)
	case ContactWebhook:
		if m.Webhook == nil {
			return errors.New("deadhand: webhook escalation is not configured")
		}
		return m.Webhook.Notify(ctx, c, subject, body)
	default:
		return fmt.Errorf("deadhand: unsupported contact kind %q", c.Kind)
	}
}

/* ------------------------------------------------------------- email ----- */

// SMTPConfig describes an outbound mail server.
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
}

// Configured reports whether email escalation can be attempted.
func (c SMTPConfig) Configured() bool { return c.Host != "" && c.From != "" }

// EmailNotifier sends escalation mail over SMTP.
type EmailNotifier struct {
	cfg SMTPConfig
}

// NewEmailNotifier builds an email notifier.
func NewEmailNotifier(cfg SMTPConfig) *EmailNotifier { return &EmailNotifier{cfg: cfg} }

// Notify sends one message.
func (e *EmailNotifier) Notify(ctx context.Context, c Contact, subject, body string) error {
	if !e.cfg.Configured() {
		return errors.New("deadhand: SMTP is not configured")
	}
	if err := validateEmail(c.Address); err != nil {
		return err
	}

	port := e.cfg.Port
	if port == 0 {
		port = 587
	}
	addr := net.JoinHostPort(e.cfg.Host, fmt.Sprint(port))

	msg := buildMessage(e.cfg.From, c.Address, subject, body)

	// Dial with a deadline so a black-holed mail server cannot wedge the
	// escalation loop — this runs unattended, on a schedule that matters.
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("deadhand: connecting to %s: %w", addr, err)
	}

	client, err := smtp.NewClient(conn, e.cfg.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("deadhand: SMTP handshake with %s: %w", addr, err)
	}
	defer func() { _ = client.Close() }()

	// STARTTLS whenever the server offers it. Escalation mail says when
	// someone's dead man's switch is about to fire; sending that in the clear
	// across the internet would be careless.
	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{ServerName: e.cfg.Host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("deadhand: STARTTLS with %s: %w", addr, err)
		}
	}

	if e.cfg.Username != "" {
		auth := smtp.PlainAuth("", e.cfg.Username, e.cfg.Password, e.cfg.Host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("deadhand: SMTP auth: %w", err)
		}
	}

	if err := client.Mail(e.cfg.From); err != nil {
		return fmt.Errorf("deadhand: MAIL FROM: %w", err)
	}
	if err := client.Rcpt(c.Address); err != nil {
		return fmt.Errorf("deadhand: RCPT TO: %w", err)
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("deadhand: DATA: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		_ = w.Close()
		return fmt.Errorf("deadhand: writing message: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("deadhand: finishing message: %w", err)
	}
	return client.Quit()
}

// buildMessage assembles a minimal RFC 5322 message.
func buildMessage(from, to, subject, body string) []byte {
	var b bytes.Buffer

	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	// Encode the subject so non-ASCII survives, and so a newline smuggled into
	// a switch name cannot inject extra headers.
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", sanitiseHeader(subject)))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("Auto-Submitted: auto-generated\r\n")
	b.WriteString("\r\n")

	// Dot-stuff, so a line consisting of a single dot cannot end the message
	// early.
	for _, line := range strings.Split(strings.ReplaceAll(body, "\r\n", "\n"), "\n") {
		if strings.HasPrefix(line, ".") {
			b.WriteString(".")
		}
		b.WriteString(line)
		b.WriteString("\r\n")
	}
	return b.Bytes()
}

// sanitiseHeader strips CR and LF, which are the header-injection vector.
func sanitiseHeader(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
}

func validateEmail(addr string) error {
	if addr == "" {
		return errors.New("deadhand: empty email address")
	}
	if strings.ContainsAny(addr, "\r\n") {
		return errors.New("deadhand: email address contains control characters")
	}
	at := strings.LastIndex(addr, "@")
	if at < 1 || at == len(addr)-1 || !strings.Contains(addr[at+1:], ".") {
		return fmt.Errorf("deadhand: %q is not a usable email address", addr)
	}
	return nil
}

/* ----------------------------------------------------------- webhook ----- */

// WebhookNotifier POSTs escalation events to a URL.
//
// Useful for anything with an inbound webhook — a chat channel, a phone alert,
// a self-hosted script — without denly needing to integrate with each.
type WebhookNotifier struct {
	Client *http.Client
}

// NewWebhookNotifier builds a webhook notifier.
func NewWebhookNotifier() *WebhookNotifier {
	return &WebhookNotifier{Client: &http.Client{Timeout: 20 * time.Second}}
}

// Notify posts a JSON body to the contact's URL.
func (n *WebhookNotifier) Notify(ctx context.Context, c Contact, subject, body string) error {
	if !strings.HasPrefix(c.Address, "https://") && !strings.HasPrefix(c.Address, "http://") {
		return fmt.Errorf("deadhand: webhook address must be an http(s) URL, got %q", c.Address)
	}

	payload, err := json.Marshal(map[string]string{
		"source":  "denly",
		"subject": subject,
		"body":    body,
	})
	if err != nil {
		return fmt.Errorf("deadhand: encoding webhook payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Address, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("deadhand: building webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := n.Client
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("deadhand: posting webhook: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// The URL itself can be a secret (Slack-style tokens live in the path),
		// so report the status without echoing the destination.
		return fmt.Errorf("deadhand: webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}
