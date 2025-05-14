package models

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// Command represents a shell command to be executed
type Command struct {
	Raw         string    // Raw command string
	URL         string    // Extracted URL from the command
	Domain      string    // Extracted domain from the URL
	OutputFile  string    // Output file path extracted from the command
	LastRun     time.Time // When the command was last executed
	LastHash    string    // Hash of the last execution's output
	LastOutput  []byte    // The output from the last execution
	CommandType string    // Type of command (ffuf, x8, etc.)
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
				c.ExtractDomain()
				return
			}
			c.URL = part
			c.ExtractDomain()
			return
		}
	}
}

// ExtractDomain gets the domain from the URL
func (c *Command) ExtractDomain() {
	if c.URL == "" {
		return
	}

	domain := c.URL
	if strings.HasPrefix(domain, "http://") || strings.HasPrefix(domain, "https://") {
		parts := strings.SplitN(domain, "/", 3)
		if len(parts) > 2 {
			domain = parts[2]
		}
	}

	// Further clean the domain (remove port, etc.)
	if strings.Contains(domain, ":") {
		domain = strings.Split(domain, ":")[0]
	}

	c.Domain = domain
}

// DetermineCommandType identifies if the command is ffuf, x8, etc.
func (c *Command) DetermineCommandType() {
	cmdLower := strings.ToLower(c.Raw)
	switch {
	case strings.Contains(cmdLower, "ffuf"):
		c.CommandType = "ffuf"
	case strings.Contains(cmdLower, "x8"):
		c.CommandType = "x8"
	default:
		c.CommandType = "other"
	}
}

// GetOutputFilePaths returns the paths for new and old output files
func (c *Command) GetOutputFilePaths() (newFile, oldFile string) {
	if c.Domain == "" {
		return "", ""
	}

	var baseDir string
	switch c.CommandType {
	case "ffuf":
		baseDir = filepath.Join("res_files", c.Domain+"_F")
	case "x8":
		baseDir = filepath.Join("res_files", c.Domain+"_X")
	default:
		baseDir = filepath.Join("res_files", c.Domain)
	}

	newFile = filepath.Join(baseDir, c.Domain+"_new.txt")
	oldFile = filepath.Join(baseDir, c.Domain+"_old.txt")

	return newFile, oldFile
}

// GetModifiedCommand returns the command with output flag appended
func (c *Command) GetModifiedCommand() string {
	if c.Domain == "" {
		return c.Raw
	}

	newFile, _ := c.GetOutputFilePaths()
	if newFile == "" {
		return c.Raw
	}

	// Check if the command already has an output flag
	cmdLower := strings.ToLower(c.Raw)
	if strings.Contains(cmdLower, " -o ") || strings.Contains(cmdLower, " --output ") {
		// Replace existing output flag
		cmd := c.Raw
		if strings.Contains(cmdLower, " -o ") {
			parts := strings.Split(cmd, " -o ")
			if len(parts) > 1 {
				// Find the end of the output path (next flag or end of string)
				outputPart := parts[1]
				outputEnd := len(outputPart)
				for i, ch := range outputPart {
					if ch == ' ' && i > 0 && outputPart[i-1] != '\\' {
						outputEnd = i
						break
					}
				}

				cmd = parts[0] + " -o " + newFile + outputPart[outputEnd:]
			}
		} else if strings.Contains(cmdLower, " --output ") {
			parts := strings.Split(cmd, " --output ")
			if len(parts) > 1 {
				// Find the end of the output path (next flag or end of string)
				outputPart := parts[1]
				outputEnd := len(outputPart)
				for i, ch := range outputPart {
					if ch == ' ' && i > 0 && outputPart[i-1] != '\\' {
						outputEnd = i
						break
					}
				}

				cmd = parts[0] + " --output " + newFile + outputPart[outputEnd:]
			}
		}
		return cmd
	}

	// Append appropriate output flag based on command type
	switch c.CommandType {
	case "ffuf":
		return c.Raw + " -o " + newFile
	case "x8":
		return c.Raw + " -o " + newFile + " -O json"
	default:
		return c.Raw
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
	cmd.DetermineCommandType()

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
	} else if r.HasChanged {
		status = "Changed"
	}

	return fmt.Sprintf("Command: %s, Status: %s, Duration: %v", r.Command.Raw, status, r.TimeTaken)
}
