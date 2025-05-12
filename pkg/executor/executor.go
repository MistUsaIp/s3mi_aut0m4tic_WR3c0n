package executor

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/avanguard/watchtower/pkg/models"
	"github.com/sirupsen/logrus"
)

// CommandExecutor handles execution of commands
type CommandExecutor struct {
	logger              *logrus.Logger
	maxWorkers          int // Maximum number of concurrent workers
	queue               chan *models.Command
	results             chan *models.CommandResult
	wg                  sync.WaitGroup
	activeCommands      int32      // Counter for currently running commands
	mu                  sync.Mutex // Mutex for thread-safe updates to activeCommands
	commandDoneCallback func()     // Callback that's triggered when a command completes
}

// NewCommandExecutor creates a new CommandExecutor
func NewCommandExecutor(logger *logrus.Logger, maxWorkers int) *CommandExecutor {
	// Create res_files directory if it doesn't exist
	if err := os.MkdirAll("res_files", 0755); err != nil {
		logger.Errorf("Failed to create res_files directory: %v", err)
	}

	executor := &CommandExecutor{
		logger:     logger,
		maxWorkers: maxWorkers,
		queue:      make(chan *models.Command, 100), // Buffer size of 100 for the queue
		results:    make(chan *models.CommandResult, 100),
	}

	// Start the worker pool
	executor.startWorkers()

	return executor
}

// SetCommandDoneCallback sets a callback function that will be called when a command completes
func (e *CommandExecutor) SetCommandDoneCallback(callback func()) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.commandDoneCallback = callback
}

// incrementActiveCommands safely increases the active commands counter
func (e *CommandExecutor) incrementActiveCommands() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.activeCommands++
	e.logger.Infof("Command started. Active commands: %d/%d", e.activeCommands, e.maxWorkers)
}

// decrementActiveCommands safely decreases the active commands counter
func (e *CommandExecutor) decrementActiveCommands() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.activeCommands--
	e.logger.Infof("Command completed. Active commands: %d/%d", e.activeCommands, e.maxWorkers)

	// Trigger callback if set
	if e.commandDoneCallback != nil {
		e.commandDoneCallback()
	}
}

// GetActiveCommandCount returns the current number of running commands
func (e *CommandExecutor) GetActiveCommandCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return int(e.activeCommands)
}

// startWorkers initializes the worker pool
func (e *CommandExecutor) startWorkers() {
	for i := 0; i < e.maxWorkers; i++ {
		e.wg.Add(1)
		go func(workerID int) {
			defer e.wg.Done()
			e.logger.Debugf("Worker %d started", workerID)

			for cmd := range e.queue {
				e.logger.Debugf("Worker %d processing command: %s", workerID, cmd.Raw)
				result := e.ExecuteCommand(context.Background(), cmd)
				e.results <- result
			}
		}(i)
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
	// Increment the active commands counter
	e.incrementActiveCommands()
	// Ensure we decrement the counter when done
	defer e.decrementActiveCommands()

	startTime := time.Now()
	e.logger.Infof("Executing command: %s", cmd.Raw)

	// Create a modified command that writes to res_files directory
	modifiedCmd := cmd.Raw
	if cmd.OutputFile != "" {
		// Get the base filename
		baseName := filepath.Base(cmd.OutputFile)
		// Create new path in res_files directory
		newOutputFile := filepath.Join("res_files", baseName)
		// Replace the output file path in the command
		modifiedCmd = strings.Replace(cmd.Raw, cmd.OutputFile, newOutputFile, 1)
		// Update the command's output file path
		cmd.OutputFile = newOutputFile
	}

	// Execute command using bash
	execCmd := exec.CommandContext(ctx, "bash", "-c", modifiedCmd)
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
	e.logger.Infof("Starting execution with %d parallel workers", e.maxWorkers)

	// Create a channel to control parallel execution
	parallelChan := make(chan struct{}, e.maxWorkers)

	// Send commands to the queue with parallel execution control
	for _, cmdGroup := range urlGroups {
		for _, cmd := range cmdGroup {
			select {
			case parallelChan <- struct{}{}: // Acquire a parallel execution slot
				select {
				case e.queue <- cmd:
					e.logger.Debugf("Added command to queue: %s", cmd.Raw)
					// Release the parallel execution slot after command completes
					go func() {
						<-e.results    // Wait for the command to complete
						<-parallelChan // Release the slot
					}()
				case <-ctx.Done():
					<-parallelChan // Release the slot if context is cancelled
					e.logger.Warn("Context cancelled while adding commands to queue")
					return nil
				}
			case <-ctx.Done():
				e.logger.Warn("Context cancelled while waiting for parallel execution slot")
				return nil
			}
		}
	}

	// Close the queue to signal no more commands will be added
	close(e.queue)

	// Collect results
	var results []*models.CommandResult
	for result := range e.results {
		results = append(results, result)
	}

	// Wait for all workers to finish
	e.wg.Wait()

	// Create new channels for the next execution
	e.queue = make(chan *models.Command, 100)
	e.results = make(chan *models.CommandResult, 100)
	e.startWorkers()

	return results
}
