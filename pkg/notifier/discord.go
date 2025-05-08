package notifier

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
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

// SendAlert sends a notification to Discord about a command result
func (d *DiscordNotifier) SendAlert(result *models.CommandResult) error {
	if !result.HasChanged && result.Error == nil {
		// No need to send alert if nothing changed and there was no error
		return nil
	}

	// Create the message
	message := DiscordMessage{
		Username: "WatchTower Monitor",
	}

	// Color codes: red for error, green for changes
	color := 65280 // Green
	if result.Error != nil {
		color = 16711680 // Red
	}

	// Build the message content
	description := fmt.Sprintf("Command: `%s`\n", truncateString(result.Command.Raw, 100))
	description += fmt.Sprintf("Executed at: %s\n", result.ExecutedAt.Format(time.RFC3339))

	if result.Error != nil {
		description += fmt.Sprintf("Error: %v\n", result.Error)
		message.Content = "⚠️ Error executing command!"
	} else if result.HasChanged {
		description += "Output has changed since last execution"
		message.Content = "🔍 Change detected in command output!"
	}

	// Create the main embed
	embed := DiscordEmbed{
		Title:       "Command Execution Result",
		Description: description,
		Color:       color,
		Timestamp:   time.Now().Format(time.RFC3339),
	}

	// Add differences as field if available
	if result.HasChanged && result.Differences != "" {
		// Discord has a 1024 character limit per field value
		// and 4096 character limit for the entire description
		diffText := truncateString(result.Differences, 1024)

		// Add as a field rather than in the description to keep it separate
		embed.Fields = []EmbedField{
			{
				Name:   "Differences Detected",
				Value:  "```diff\n" + diffText + "\n```",
				Inline: false,
			},
		}
	}

	message.Embeds = []DiscordEmbed{embed}

	// Convert message to JSON
	jsonData, err := json.Marshal(message)
	if err != nil {
		d.logger.Errorf("Failed to marshal Discord message: %v", err)
		return err
	}

	// Send the HTTP request
	resp, err := d.client.Post(d.webhookURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		d.logger.Errorf("Failed to send Discord notification: %v", err)
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		d.logger.Errorf("Discord API returned non-2xx status code: %d", resp.StatusCode)
		return fmt.Errorf("discord API returned status code %d", resp.StatusCode)
	}

	d.logger.Infof("Successfully sent Discord notification for command: %s", result.Command.Raw)
	return nil
}
