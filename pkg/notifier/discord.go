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
	"sync"
	"time"

	"github.com/avanguard/watchtower/pkg/models"
	"github.com/sirupsen/logrus"
)

// DiscordNotifier handles notifications to Discord via webhooks
type DiscordNotifier struct {
	webhookURL string
	logger     *logrus.Logger
	client     *http.Client

	// Rate limiting
	rateLimitMu          sync.Mutex
	requestTimestamps    []time.Time
	maxRequestsPerWindow int
	rateLimitWindow      time.Duration
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
		// Set up rate limiting for Discord (5 requests per 2 seconds)
		requestTimestamps:    make([]time.Time, 0, 5),
		maxRequestsPerWindow: 5,
		rateLimitWindow:      2 * time.Second,
	}
}

// truncateString cuts a string to the max length and adds ellipsis if needed
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// waitForRateLimit ensures we don't exceed Discord's rate limit of 5 requests per 2 seconds
func (d *DiscordNotifier) waitForRateLimit() {
	d.rateLimitMu.Lock()
	defer d.rateLimitMu.Unlock()

	now := time.Now()

	// Clean up old timestamps outside the window
	cutoff := now.Add(-d.rateLimitWindow)
	currentWindow := make([]time.Time, 0, d.maxRequestsPerWindow)

	for _, timestamp := range d.requestTimestamps {
		if timestamp.After(cutoff) {
			currentWindow = append(currentWindow, timestamp)
		}
	}

	d.requestTimestamps = currentWindow

	// If we've reached the limit, wait until we can make another request
	if len(d.requestTimestamps) >= d.maxRequestsPerWindow {
		oldestRequest := d.requestTimestamps[0]
		timeToWait := oldestRequest.Add(d.rateLimitWindow).Sub(now)

		if timeToWait > 0 {
			d.logger.Infof("Rate limit reached: waiting %v before sending next Discord notification", timeToWait)
			d.rateLimitMu.Unlock()
			time.Sleep(timeToWait)
			d.rateLimitMu.Lock()
		}

		// After waiting, remove the oldest timestamp
		if len(d.requestTimestamps) > 0 {
			d.requestTimestamps = d.requestTimestamps[1:]
		}
	}

	// Add the current request timestamp
	d.requestTimestamps = append(d.requestTimestamps, now)
	d.logger.Debugf("Current Discord rate limit window: %d/%d requests", len(d.requestTimestamps), d.maxRequestsPerWindow)
}

// SendAlert sends a notification to Discord when command output changes
func (d *DiscordNotifier) SendAlert(result *models.CommandResult) error {
	if d.webhookURL == "" {
		return fmt.Errorf("webhook URL not configured")
	}

	d.logger.Infof("Preparing Discord notification for command: %s", result.Command.Raw)

	// Build the message content
	var contentBuilder strings.Builder
	
	// Use a more distinct heading with emoji 
	if result.Error != nil {
		contentBuilder.WriteString("## :x: Command Error\n\n")
	} else if result.HasChanged {
		contentBuilder.WriteString("## :rotating_light: Scan Results Changed\n\n")
	} else {
		contentBuilder.WriteString("## :white_check_mark: Scan Completed\n\n")
	}
	
	// Command information section
	contentBuilder.WriteString("### Command Details\n")
	contentBuilder.WriteString(fmt.Sprintf(":arrow_right: `%s`\n\n", result.Command.Raw))
	contentBuilder.WriteString(fmt.Sprintf(":clock1: **Time:** %s\n", result.ExecutedAt.Format("2006-01-02 15:04:05")))
	
	if result.Command.Domain != "" {
		contentBuilder.WriteString(fmt.Sprintf(":globe_with_meridians: **Target:** `%s`\n", result.Command.Domain))
		contentBuilder.WriteString(fmt.Sprintf(":wrench: **Tool:** `%s`\n", result.Command.CommandType))
		if result.Command.ScanType != "" {
			contentBuilder.WriteString(fmt.Sprintf(":mag: **Scan Type:** `%s`\n", result.Command.ScanType))
		}
	}
	
	contentBuilder.WriteString(fmt.Sprintf(":hourglass: **Duration:** %v\n\n", result.TimeTaken))
	
	// Storage path if available
	if result.StoragePath != "" {
		contentBuilder.WriteString(fmt.Sprintf(":file_folder: **Results Path:** `%s`\n\n", result.StoragePath))
	}

	// Error details if present
	if result.Error != nil {
		contentBuilder.WriteString("### :warning: Error\n")
		contentBuilder.WriteString(fmt.Sprintf("`%v`\n\n", result.Error))
		
		// Include stderr if available
		if stderr := getStderrFromError(result.Error); stderr != "" {
			contentBuilder.WriteString("**Error Details:**\n```\n")
			contentBuilder.WriteString(stderr)
			contentBuilder.WriteString("\n```\n")
		}
	} else if result.HasChanged {
		// Changes detected section
		contentBuilder.WriteString("### :clipboard: Changes Detected\n\n")

		// Make the differences more visible with a color-coded diff block
		contentBuilder.WriteString("```diff\n")
		
		// Check if differences information is available
		if result.Differences == "" {
			contentBuilder.WriteString("# Changes detected but no details available\n")
		} else {
			contentBuilder.WriteString(result.Differences)
		}
		contentBuilder.WriteString("\n```\n")

		// Add output file path if available
		if result.Command.OutputFile != "" {
			contentBuilder.WriteString(fmt.Sprintf("\n**Output File:** `%s`\n", result.Command.OutputFile))
		}
	} else {
		contentBuilder.WriteString("### :information_source: No Changes\n")
		contentBuilder.WriteString("Scan completed successfully with no changes detected.\n")
	}
	
	// Add timestamp stamp at the end
	contentBuilder.WriteString(fmt.Sprintf("\n\n_Notification sent at: %s_", time.Now().Format("2006-01-02 15:04:05")))

	d.logger.Debugf("Discord notification content prepared (%d chars)", contentBuilder.Len())

	// Prepare the webhook payload - use embed format for longer content
	content := contentBuilder.String()
	
	// Get a color based on status (red for error, yellow for changes, green for success)
	var color int
	if result.Error != nil {
		color = 0xFF0000 // Red
	} else if result.HasChanged {
		color = 0xFFCC00 // Yellow
	} else {
		color = 0x00FF00 // Green
	}
	
	// Always use embed format for consistent formatting
	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title": getEmbedTitle(result),
				"description": content,
				"color": color,
				"timestamp": time.Now().Format(time.RFC3339),
			},
		},
	}

	// Convert payload to JSON
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal Discord payload: %v", err)
	}

	// Try multiple times with exponential backoff
	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		// Wait for rate limit before sending request
		d.waitForRateLimit()

		// Send the webhook request
		d.logger.Debugf("Sending Discord webhook request (attempt %d/%d)", i+1, maxRetries)
		resp, err := d.client.Post(d.webhookURL, "application/json", bytes.NewBuffer(jsonPayload))

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

// getEmbedTitle returns an appropriate title for the Discord embed based on result
func getEmbedTitle(result *models.CommandResult) string {
	domain := result.Command.Domain
	if domain == "" {
		domain = "Unknown Domain"
	}
	
	toolType := result.Command.CommandType
	if toolType == "" {
		toolType = "scan"
	}
	
	if result.Error != nil {
		return fmt.Sprintf("❌ %s %s Failed", strings.ToUpper(toolType), domain)
	} else if result.HasChanged {
		return fmt.Sprintf("⚠️ %s %s Changes Detected", strings.ToUpper(toolType), domain)
	} else {
		return fmt.Sprintf("✅ %s %s Completed", strings.ToUpper(toolType), domain)
	}
}

// getStderrFromError attempts to extract stderr output from exec.ExitError
func getStderrFromError(err error) string {
	if exitErr, ok := err.(*exec.ExitError); ok {
		return string(exitErr.Stderr)
	}
	return ""
}

// SendCompletionNotification sends a notification to Discord when all commands have finished
func (d *DiscordNotifier) SendCompletionNotification(totalCommands int, changedCount int, errorsCount int) error {
	if d.webhookURL == "" {
		return fmt.Errorf("webhook URL not configured")
	}

	d.logger.Infof("Preparing completion notification for %d commands", totalCommands)

	// Build the message content
	var contentBuilder strings.Builder
	
	// Use a completion heading with emoji
	contentBuilder.WriteString("## :white_check_mark: All Jobs Complete\n\n")
	
	// Statistics section
	contentBuilder.WriteString("### :bar_chart: Execution Summary\n")
	contentBuilder.WriteString(fmt.Sprintf(":ballot_box_with_check: **Total Commands:** %d\n", totalCommands))
	contentBuilder.WriteString(fmt.Sprintf(":rotating_light: **Changed Results:** %d\n", changedCount))
	contentBuilder.WriteString(fmt.Sprintf(":x: **Errors:** %d\n", errorsCount))
	
	// Timestamp
	contentBuilder.WriteString(fmt.Sprintf("\n\n_Completed at: %s_", time.Now().Format("2006-01-02 15:04:05")))

	d.logger.Debugf("Completion notification content prepared (%d chars)", contentBuilder.Len())

	// Create the webhook message
	message := DiscordMessage{
		Username: "WatchTower Monitor",
		Content:  contentBuilder.String(),
	}

	return d.sendWebhookMessage(message)
}

// sendWebhookMessage sends a message to Discord webhook with appropriate rate limiting and retries
func (d *DiscordNotifier) sendWebhookMessage(message DiscordMessage) error {
	// Convert message to JSON
	jsonPayload, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal Discord payload: %v", err)
	}

	// Try multiple times with exponential backoff
	maxRetries := 3
	for i := 0; i < maxRetries; i++ {
		// Wait for rate limit before sending request
		d.waitForRateLimit()

		// Send the webhook request
		d.logger.Debugf("Sending Discord webhook request (attempt %d/%d)", i+1, maxRetries)
		resp, err := d.client.Post(d.webhookURL, "application/json", bytes.NewBuffer(jsonPayload))

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
		d.logger.Infof("Discord webhook message sent successfully")
		return nil
	}

	// This point should not be reached, but just in case
	return fmt.Errorf("failed to send Discord webhook message after %d attempts", maxRetries)
}
