package models

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Command represents a shell command to be executed
type Command struct {
	Raw        string    // Raw command string
	URL        string    // Extracted URL from the command
	OutputFile string    // Output file path extracted from the command
	LastRun    time.Time // When the command was last executed
	LastHash   string    // Hash of the last execution's output
	LastOutput []byte    // The output from the last execution
}

// Extract the URL from a command string
func (c *Command) ExtractURL() {
	// This is a simple extractor that looks for https:// in the command
	// For production, you might want to make this more robust
	parts := strings.Split(c.Raw, " ")
	for i, part := range parts {
		if strings.HasPrefix(part, "https://") || strings.HasPrefix(part, "http://") {
			// If this is the -u parameter, take the next part as the URL
			if part == "-u" && i+1 < len(parts) {
				c.URL = parts[i+1]
				return
			}
			c.URL = part
			return
		}
	}
}

// Extract output file from a command string
func (c *Command) ExtractOutputFile() {
	parts := strings.Split(c.Raw, " ")
	for i, part := range parts {
		if part == "-o" && i+1 < len(parts) {
			c.OutputFile = parts[i+1]
			return
		}
	}
}

// NewCommand creates a new command instance
func NewCommand(rawCmd string) *Command {
	cmd := &Command{
		Raw: rawCmd,
	}
	cmd.ExtractURL()
	cmd.ExtractOutputFile()
	return cmd
}

// HashFile generates an MD5 hash of the given content
func HashFile(content []byte) string {
	hasher := md5.New()
	hasher.Write(content)
	return hex.EncodeToString(hasher.Sum(nil))
}

// CommandResult represents the result of a command execution
type CommandResult struct {
	Command     *Command
	Output      []byte
	OutputHash  string
	Error       error
	TimeTaken   time.Duration
	HasChanged  bool
	ExecutedAt  time.Time
	Differences string // String representation of the differences between runs
}

// String returns a readable string representation of the command result
func (r *CommandResult) String() string {
	status := "Success"
	if r.Error != nil {
		status = fmt.Sprintf("Error: %v", r.Error)
	}

	changeStatus := ""
	if r.HasChanged {
		changeStatus = " (CHANGED)"
	}

	return fmt.Sprintf("[%s] %s - %s%s (took: %v)",
		r.ExecutedAt.Format("2006-01-02 15:04:05"),
		r.Command.Raw,
		status,
		changeStatus,
		r.TimeTaken)
}
