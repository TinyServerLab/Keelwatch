// Package notify sends alerts to ntfy, Discord, Telegram, Slack-compatible
// or generic JSON webhooks. Configured from environment variables.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type Message struct {
	Title    string `json:"title"`
	Body     string `json:"body"`
	Severity string `json:"severity"`
	URL      string `json:"url,omitempty"`
}

type Config struct {
	NtfyURL        string // full topic URL, e.g. https://ntfy.sh/my-topic
	NtfyToken      string
	DiscordWebhook string
	SlackWebhook   string
	TelegramToken  string
	TelegramChat   string
	WebhookURL     string // generic JSON POST of Message
}

type Notifier struct {
	cfg    Config
	client *http.Client
}

func New(cfg Config) *Notifier {
	return &Notifier{cfg: cfg, client: &http.Client{Timeout: 15 * time.Second}}
}

// Channels lists configured channel names (never their secrets).
func (n *Notifier) Channels() []string {
	var c []string
	if n.cfg.NtfyURL != "" {
		c = append(c, "ntfy")
	}
	if n.cfg.DiscordWebhook != "" {
		c = append(c, "discord")
	}
	if n.cfg.SlackWebhook != "" {
		c = append(c, "slack")
	}
	if n.cfg.TelegramToken != "" && n.cfg.TelegramChat != "" {
		c = append(c, "telegram")
	}
	if n.cfg.WebhookURL != "" {
		c = append(c, "webhook")
	}
	return c
}

func (n *Notifier) Enabled() bool { return len(n.Channels()) > 0 }

func (n *Notifier) Send(ctx context.Context, m Message) error {
	var errs []error
	body := m.Body
	if m.URL != "" {
		body += "\n" + m.URL
	}
	if u := n.cfg.NtfyURL; u != "" {
		prio := map[string]string{"critical": "urgent", "high": "high", "medium": "default"}[m.Severity]
		if prio == "" {
			prio = "low"
		}
		h := map[string]string{"Title": m.Title, "Priority": prio, "Tags": "shield"}
		if n.cfg.NtfyToken != "" {
			h["Authorization"] = "Bearer " + n.cfg.NtfyToken
		}
		if m.URL != "" {
			h["Click"] = m.URL
		}
		errs = append(errs, n.post(ctx, u, "text/plain", []byte(m.Body), h))
	}
	if u := n.cfg.DiscordWebhook; u != "" {
		b, _ := json.Marshal(map[string]any{"username": "Keelwatch", "content": trim("**"+m.Title+"**\n"+body, 1900)})
		errs = append(errs, n.post(ctx, u, "application/json", b, nil))
	}
	if u := n.cfg.SlackWebhook; u != "" {
		b, _ := json.Marshal(map[string]any{"text": trim("*"+m.Title+"*\n"+body, 3000)})
		errs = append(errs, n.post(ctx, u, "application/json", b, nil))
	}
	if n.cfg.TelegramToken != "" && n.cfg.TelegramChat != "" {
		u := "https://api.telegram.org/bot" + n.cfg.TelegramToken + "/sendMessage"
		b, _ := json.Marshal(map[string]any{"chat_id": n.cfg.TelegramChat, "text": trim(m.Title+"\n\n"+body, 4000), "disable_web_page_preview": true})
		err := n.post(ctx, u, "application/json", b, nil)
		if err != nil {
			err = errors.New("telegram: request failed") // never echo the bot token
		}
		errs = append(errs, err)
	}
	if u := n.cfg.WebhookURL; u != "" {
		b, _ := json.Marshal(m)
		errs = append(errs, n.post(ctx, u, "application/json", b, nil))
	}
	return errors.Join(errs...)
}

func (n *Notifier) post(ctx context.Context, u, ct string, body []byte, headers map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", ct)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := n.client.Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", host(u), err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s: %s", host(u), resp.Status)
	}
	return nil
}

func host(u string) string {
	u = strings.TrimPrefix(strings.TrimPrefix(u, "https://"), "http://")
	h, _, _ := strings.Cut(u, "/")
	return h
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
