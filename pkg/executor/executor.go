package executor

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/avanguard/watchtower/pkg/models"
	"github.com/sirupsen/logrus"
)

// CommandExecutor handles execution of commands
type CommandExecutor struct {
	logger     *logrus.Logger
	maxWorkers int // Maximum number of concurrent workers
}

// NewCommandExecutor creates a new CommandExecutor
func NewCommandExecutor(logger *logrus.Logger) *CommandExecutor {
	// Set fixed number of workers to 5 for parallel execution
	maxWorkers := 5

	return &CommandExecutor{
		logger:     logger,
		maxWorkers: maxWorkers,
	}
}

// calculateDifferences compares two outputs and returns a string representation of differences
func (e *CommandExecutor) calculateDifferences(oldOutput, newOutput []byte) string {
	if len(oldOutput) == 0 {
		return "No previous output to compare with"
	}

	// Convert to strings and split by lines for comparison
	oldLines := strings.Split(string(oldOutput), "\n")
	newLines := strings.Split(string(newOutput), "\n")

	// Find added, removed, and changed lines
	added := []string{}
	removed := []string{}

	// Create maps for faster lookup
	oldMap := make(map[string]bool)
	newMap := make(map[string]bool)

	for _, line := range oldLines {
		if strings.TrimSpace(line) != "" {
			oldMap[line] = true
		}
	}

	for _, line := range newLines {
		if strings.TrimSpace(line) != "" {
			newMap[line] = true
		}
	}

	// Find removed lines (in old but not in new)
	for _, line := range oldLines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !newMap[line] {
			removed = append(removed, line)
		}
	}

	// Find added lines (in new but not in old)
	for _, line := range newLines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !oldMap[line] {
			added = append(added, line)
		}
	}

	// Build the difference summary
	var diffBuilder strings.Builder

	if len(added) > 0 {
		diffBuilder.WriteString("Added lines:\n")
		for i, line := range added {
			if i < 10 { // Limit to first 10 lines for readability
				diffBuilder.WriteString(fmt.Sprintf("+ %s\n", line))
			} else {
				diffBuilder.WriteString(fmt.Sprintf("... and %d more added lines\n", len(added)-10))
				break
			}
		}
	}

	if len(removed) > 0 {
		if diffBuilder.Len() > 0 {
			diffBuilder.WriteString("\n")
		}
		diffBuilder.WriteString("Removed lines:\n")
		for i, line := range removed {
			if i < 10 { // Limit to first 10 lines for readability
				diffBuilder.WriteString(fmt.Sprintf("- %s\n", line))
			} else {
				diffBuilder.WriteString(fmt.Sprintf("... and %d more removed lines\n", len(removed)-10))
				break
			}
		}
	}

	if diffBuilder.Len() == 0 {
		return "Changes detected but exact differences couldn't be determined"
	}

	return diffBuilder.String()
}

// ExecuteCommand runs a shell command and returns its result
func (e *CommandExecutor) ExecuteCommand(ctx context.Context, cmd *models.Command) *models.CommandResult {
	startTime := time.Now()
	e.logger.Infof("Executing command: %s", cmd.Raw)

	// Execute command using bash
	execCmd := exec.CommandContext(ctx, "bash", "-c", cmd.Raw)
	var stderr, stdout bytes.Buffer
	execCmd.Stderr = &stderr
	execCmd.Stdout = &stdout

	err := execCmd.Run()

	result := &models.CommandResult{
		Command:    cmd,
		ExecutedAt: startTime,
		TimeTaken:  time.Since(startTime),
	}

	if err != nil {
		e.logger.Errorf("Command execution failed: %v, stderr: %s", err, stderr.String())
		result.Error = err
		return result
	}

	// Try to read the output file if specified
	if cmd.OutputFile != "" {
		output, err := os.ReadFile(cmd.OutputFile)
		if err != nil {
			e.logger.Warnf("Could not read output file %s: %v", cmd.OutputFile, err)
			// Still return the stdout as output
			result.Output = stdout.Bytes()
		} else {
			result.Output = output
		}
	} else {
		// If no output file, use stdout
		result.Output = stdout.Bytes()
	}

	// Calculate hash of the output
	result.OutputHash = models.HashFile(result.Output)

	// Check if output has changed
	if cmd.LastHash != "" && cmd.LastHash != result.OutputHash {
		result.HasChanged = true
		e.logger.Infof("Output changed for command: %s", cmd.Raw)

		// Calculate differences
		result.Differences = e.calculateDifferences(cmd.LastOutput, result.Output)

		// Display differences in terminal with clear formatting
		fmt.Println("\n=== Changes Detected ===")
		fmt.Printf("Command: %s\n", cmd.Raw)
		fmt.Printf("Time: %s\n", time.Now().Format("2006-01-02 15:04:05"))
		fmt.Println("\nDifferences:")
		fmt.Println(result.Differences)
		fmt.Println("=====================\n")

		e.logger.Debugf("Differences: %s", result.Differences)
	}

	// Update command's last run info
	cmd.LastRun = startTime
	cmd.LastHash = result.OutputHash
	cmd.LastOutput = result.Output

	return result
}

// executeCommandGroup executes a group of commands sequentially
func (e *CommandExecutor) executeCommandGroup(ctx context.Context, cmds []*models.Command, resultChan chan<- *models.CommandResult) {
	for _, cmd := range cmds {
		select {
		case <-ctx.Done():
			e.logger.Warn("Command execution cancelled")
			return
		default:
			result := e.ExecuteCommand(ctx, cmd)
			resultChan <- result
		}
	}
}

// ExecuteGroupedCommands executes commands grouped by URL to avoid conflicts
func (e *CommandExecutor) ExecuteGroupedCommands(ctx context.Context, commands []*models.Command) []*models.CommandResult {
	// Group commands by URL, with special handling for ffuf commands
	urlGroups := make(map[string][]*models.Command)
	for _, cmd := range commands {
		// Check if command is ffuf
		isFfuf := strings.Contains(cmd.Raw, "ffuf")

		if isFfuf {
			// For ffuf commands, group by domain to ensure only one runs at a time
			if cmd.URL == "" {
				// If no URL could be extracted, use the whole command as key
				urlGroups[cmd.Raw] = append(urlGroups[cmd.Raw], cmd)
			} else {
				// Extract domain from URL
				domain := cmd.URL
				if strings.HasPrefix(domain, "http://") || strings.HasPrefix(domain, "https://") {
					parts := strings.SplitN(domain, "/", 3)
					if len(parts) > 2 {
						domain = parts[2]
					}
				}
				urlGroups[domain] = append(urlGroups[domain], cmd)
			}
		} else {
			// For non-ffuf commands (like x8), allow parallel execution on same domain
			// Use a unique key for each command to allow parallel execution
			uniqueKey := fmt.Sprintf("%s_%d", cmd.URL, len(urlGroups))
			urlGroups[uniqueKey] = append(urlGroups[uniqueKey], cmd)
		}
	}

	e.logger.Infof("Grouped %d commands into %d URL groups for execution", len(commands), len(urlGroups))

	// Create a channel for command groups
	urlGroupChan := make(chan []*models.Command, len(urlGroups))
	resultChan := make(chan *models.CommandResult, len(commands))

	// Start worker pool with fixed number of workers (5)
	workerCount := e.maxWorkers
	e.logger.Debugf("Starting %d workers for parallel execution", workerCount)

	// Start worker goroutines
	var wg sync.WaitGroup
	for i := 0; i < workerCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for cmdGroup := range urlGroupChan {
				e.executeCommandGroup(ctx, cmdGroup, resultChan)
			}
		}()
	}

	// Send command groups to workers
	for _, cmdGroup := range urlGroups {
		urlGroupChan <- cmdGroup
	}
	close(urlGroupChan)

	// Start a goroutine to close the result channel when all workers are done
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	var results []*models.CommandResult
	for result := range resultChan {
		results = append(results, result)
	}

	return results
}
