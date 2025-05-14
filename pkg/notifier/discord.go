package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/avanguard/watchtower/pkg/models"
	"github.com/sirupsen/logrus"
)

// DiscordNotifier handles notifications to Discord via webhooks
type DiscordNotifier struct {
	webhookURL string
	logger     *logrus.Logger
	client     *http.Client
}

// DiscordEmbed represents a Discord embed object
type DiscordEmbed struct {
	Title       string       `json:"title"`
	Description string       `json:"description"`
	Color       int          `json:"color"` // RGB color value
	Timestamp   string       `json:"timestamp"`
	Fields      []EmbedField `json:"fields,omitempty"`
}

// EmbedField represents a field in a Discord embed
type EmbedField struct {
	Name   string `json:"name"`
	Value  string `json:"value"`
	Inline bool   `json:"inline,omitempty"`
}

// DiscordMessage represents a Discord webhook message
type DiscordMessage struct {
	Username  string         `json:"username"`
	Content   string         `json:"content"`
	Embeds    []DiscordEmbed `json:"embeds,omitempty"`
	AvatarURL string         `json:"avatar_url,omitempty"`
}

// NewDiscordNotifier creates a new Discord notifier
func NewDiscordNotifier(webhookURL string, logger *logrus.Logger) *DiscordNotifier {
	return &DiscordNotifier{
		webhookURL: webhookURL,
		logger:     logger,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// truncateString cuts a string to the max length and adds ellipsis if needed
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// SendAlert sends a notification to Discord when command output changes
func (d *DiscordNotifier) SendAlert(result *models.CommandResult) error {
	if d.webhookURL == "" {
		return fmt.Errorf("webhook URL not configured")
	}

	d.logger.Infof("Preparing Discord notification for command: %s", result.Command.Raw)

	// Build the message content
	var contentBuilder strings.Builder
	contentBuilder.WriteString("## :warning: Command Output Changed\n\n")
	contentBuilder.WriteString(fmt.Sprintf("**Command:** `%s`\n", result.Command.Raw))
	contentBuilder.WriteString(fmt.Sprintf("**Time:** %s\n", result.ExecutedAt.Format("2006-01-02 15:04:05")))

	if result.Command.Domain != "" {
		contentBuilder.WriteString(fmt.Sprintf("**Domain:** `%s`\n", result.Command.Domain))
		contentBuilder.WriteString(fmt.Sprintf("**Type:** `%s`\n", result.Command.CommandType))
	}

	contentBuilder.WriteString(fmt.Sprintf("**Duration:** %v\n\n", result.TimeTaken))

	if result.Error != nil {
		contentBuilder.WriteString(fmt.Sprintf("**Error:** %v\n\n", result.Error))
		// Include stderr if available
		if stderr := getStderrFromError(result.Error); stderr != "" {
			contentBuilder.WriteString("**Error Details:**\n```\n")
			contentBuilder.WriteString(stderr)
			contentBuilder.WriteString("\n```\n")
		}
	} else if result.HasChanged {
		contentBuilder.WriteString("### Differences:\n")

		// Make the differences code block for better readability
		contentBuilder.WriteString("```diff\n")
		contentBuilder.WriteString(result.Differences)
		contentBuilder.WriteString("\n```\n")

		// Add output file path
		if result.Command.OutputFile != "" {
			contentBuilder.WriteString(fmt.Sprintf("\n**Output File:** `%s`\n", result.Command.OutputFile))
		}
	}

	d.logger.Debugf("Discord notification content prepared (%d chars)", contentBuilder.Len())

	// Prepare the webhook payload - use embed format for longer content
	content := contentBuilder.String()
	var payload map[string]interface{}

	if len(content) > 2000 {
		// Use embed for longer content
		d.logger.Debugf("Using embed format for long message (%d chars)", len(content))

		// Truncate the content for the embed description
		description := content
		if len(description) > 4096 {
			description = description[:4090] + "..."
		}

		payload = map[string]interface{}{
			"embeds": []map[string]interface{}{
				{
					"title":       "Command Output Changed",
					"description": description,
					"color":       15158332, // Red
				},
			},
		}
	} else {
		// Use simple content for shorter messages
		payload = map[string]interface{}{
			"content": content,
		}
	}

	// Convert payload to JSON
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal Discord payload: %v", err)
	}

	// Try multiple times with exponential backoff
	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		// Send the webhook request
		d.logger.Debugf("Sending Discord webhook request (attempt %d/%d)", i+1, maxRetries)
		resp, err := http.Post(d.webhookURL, "application/json", bytes.NewBuffer(jsonPayload))

		if err != nil {
			d.logger.Warnf("Discord webhook request failed (attempt %d/%d): %v", i+1, maxRetries, err)
			if i < maxRetries-1 {
				// Wait with exponential backoff before retrying
				time.Sleep(time.Duration(1<<i) * time.Second)
				continue
			}
			return fmt.Errorf("failed to send Discord webhook after %d attempts: %v", maxRetries, err)
		}

		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)

		// Check response status
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			d.logger.Warnf("Discord webhook returned non-success status (attempt %d/%d): %d, body: %s",
				i+1, maxRetries, resp.StatusCode, string(body))

			// If rate limited, wait and retry
			if resp.StatusCode == 429 {
				// Parse rate limit headers if available
				retryAfter := 5 // Default 5 seconds
				if s := resp.Header.Get("Retry-After"); s != "" {
					if i, err := strconv.Atoi(s); err == nil {
						retryAfter = i
					}
				}

				if i < maxRetries-1 {
					d.logger.Infof("Rate limited by Discord, retrying after %d seconds", retryAfter)
					time.Sleep(time.Duration(retryAfter) * time.Second)
					continue
				}
			}

			if i < maxRetries-1 {
				time.Sleep(time.Duration(1<<i) * time.Second)
				continue
			}

			return fmt.Errorf("Discord webhook returned non-success status after %d attempts: %d, body: %s",
				maxRetries, resp.StatusCode, string(body))
		}

		// Success!
		d.logger.Infof("Discord notification sent successfully for command: %s", result.Command.Raw)
		return nil
	}

	// This point should not be reached, but just in case
	return fmt.Errorf("failed to send Discord notification after %d attempts", maxRetries)
}

// getStderrFromError attempts to extract stderr output from exec.ExitError
func getStderrFromError(err error) string {
	if exitErr, ok := err.(*exec.ExitError); ok {
		return string(exitErr.Stderr)
	}
	return ""
}
