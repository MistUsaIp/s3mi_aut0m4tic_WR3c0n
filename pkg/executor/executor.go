package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/avanguard/watchtower/pkg/filemanager"
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
	activeCommands      int32                    // Counter for currently running commands
	mu                  sync.Mutex               // Mutex for thread-safe updates to activeCommands
	commandDoneCallback func()                   // Callback that's triggered when a command completes
	fileManager         *filemanager.FileManager // File manager for structured storage
}

// NewCommandExecutor creates a new CommandExecutor
func NewCommandExecutor(logger *logrus.Logger, maxWorkers int) *CommandExecutor {
	// Create the file manager for structured storage
	fm, err := filemanager.NewFileManager("res_files")
	if err != nil {
		logger.Errorf("Failed to initialize file manager: %v", err)
	}

	executor := &CommandExecutor{
		logger:      logger,
		maxWorkers:  maxWorkers,
		queue:       make(chan *models.Command, 100), // Buffer size of 100 for the queue
		results:     make(chan *models.CommandResult, 100),
		fileManager: fm,
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

	// Check if both outputs are valid JSON
	var oldJSON, newJSON interface{}
	isJSON := true

	if err := json.Unmarshal(oldOutput, &oldJSON); err != nil {
		isJSON = false
	}

	if err := json.Unmarshal(newOutput, &newJSON); err != nil {
		isJSON = false
	}

	// If both are valid JSON, do a JSON-specific comparison
	if isJSON {
		return e.compareJSON(oldJSON, newJSON)
	}

	// Fall back to text comparison for non-JSON content
	return e.compareText(oldOutput, newOutput)
}

// compareJSON compares two JSON objects and returns differences in a readable format
func (e *CommandExecutor) compareJSON(oldJSON, newJSON interface{}) string {
	var diffBuilder strings.Builder

	// Compare as maps if possible
	oldMap, oldIsMap := oldJSON.(map[string]interface{})
	newMap, newIsMap := newJSON.(map[string]interface{})

	if oldIsMap && newIsMap {
		// Find added and modified keys
		addedKeys := []string{}
		modifiedKeys := map[string]string{}

		for key, newValue := range newMap {
			oldValue, exists := oldMap[key]
			if !exists {
				// Key added in new JSON
				addedKeys = append(addedKeys, key)
			} else if !reflect.DeepEqual(oldValue, newValue) {
				// Key exists but value changed
				oldValueStr := fmt.Sprintf("%v", oldValue)
				newValueStr := fmt.Sprintf("%v", newValue)
				if len(oldValueStr) > 50 {
					oldValueStr = oldValueStr[:47] + "..."
				}
				if len(newValueStr) > 50 {
					newValueStr = newValueStr[:47] + "..."
				}
				modifiedKeys[key] = fmt.Sprintf("%s → %s", oldValueStr, newValueStr)
			}
		}

		// Find deleted keys
		deletedKeys := []string{}
		for key := range oldMap {
			if _, exists := newMap[key]; !exists {
				deletedKeys = append(deletedKeys, key)
			}
		}

		// Sort keys for consistent output
		sort.Strings(addedKeys)
		sort.Strings(deletedKeys)

		// Build the difference report
		if len(addedKeys) > 0 {
			diffBuilder.WriteString("Added keys:\n")
			for _, key := range addedKeys {
				value := newMap[key]
				valueStr := fmt.Sprintf("%v", value)
				if len(valueStr) > 100 {
					valueStr = valueStr[:97] + "..."
				}
				diffBuilder.WriteString(fmt.Sprintf("+ %s: %s\n", key, valueStr))
			}
		}

		if len(modifiedKeys) > 0 {
			if diffBuilder.Len() > 0 {
				diffBuilder.WriteString("\n")
			}
			diffBuilder.WriteString("Modified keys:\n")

			// Sort modified keys for consistent output
			var keys []string
			for k := range modifiedKeys {
				keys = append(keys, k)
			}
			sort.Strings(keys)

			for _, key := range keys {
				diffBuilder.WriteString(fmt.Sprintf("* %s: %s\n", key, modifiedKeys[key]))
			}
		}

		if len(deletedKeys) > 0 {
			if diffBuilder.Len() > 0 {
				diffBuilder.WriteString("\n")
			}
			diffBuilder.WriteString("Deleted keys:\n")
			for _, key := range deletedKeys {
				value := oldMap[key]
				valueStr := fmt.Sprintf("%v", value)
				if len(valueStr) > 100 {
					valueStr = valueStr[:97] + "..."
				}
				diffBuilder.WriteString(fmt.Sprintf("- %s: %s\n", key, valueStr))
			}
		}

		if diffBuilder.Len() == 0 {
			return "JSON content changed but no specific key differences found"
		}

		return diffBuilder.String()
	}

	// Handle JSON arrays
	oldArray, oldIsArray := oldJSON.([]interface{})
	newArray, newIsArray := newJSON.([]interface{})

	if oldIsArray && newIsArray {
		diffBuilder.WriteString(fmt.Sprintf("Array length changed: %d → %d\n", len(oldArray), len(newArray)))

		// Find added/removed elements in simple cases
		if len(oldArray) < len(newArray) && len(oldArray) < 10 {
			diffBuilder.WriteString("\nAdded elements:\n")
			for i := len(oldArray); i < len(newArray) && i < 10+len(oldArray); i++ {
				valueStr := fmt.Sprintf("%v", newArray[i])
				if len(valueStr) > 100 {
					valueStr = valueStr[:97] + "..."
				}
				diffBuilder.WriteString(fmt.Sprintf("+ [%d]: %s\n", i, valueStr))
			}
		} else if len(oldArray) > len(newArray) && len(newArray) < 10 {
			diffBuilder.WriteString("\nRemoved elements:\n")
			for i := len(newArray); i < len(oldArray) && i < 10+len(newArray); i++ {
				valueStr := fmt.Sprintf("%v", oldArray[i])
				if len(valueStr) > 100 {
					valueStr = valueStr[:97] + "..."
				}
				diffBuilder.WriteString(fmt.Sprintf("- [%d]: %s\n", i, valueStr))
			}
		}

		return diffBuilder.String()
	}

	// Different types or complex changes
	return fmt.Sprintf("JSON structure changed completely.\nOld type: %T\nNew type: %T", oldJSON, newJSON)
}

// compareText compares two text outputs line by line (original implementation)
func (e *CommandExecutor) compareText(oldOutput, newOutput []byte) string {
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

	// Ensure domain extraction has been performed
	if cmd.Domain == "" && cmd.URL != "" {
		cmd.ExtractDomain()
	}

	// If domain is still empty, try to extract it from the command directly
	if cmd.Domain == "" {
		// Try to find a domain pattern in the command
		cmdParts := strings.Split(cmd.Raw, " ")
		for _, part := range cmdParts {
			// Look for typical domain patterns
			if strings.Contains(part, ".com") || strings.Contains(part, ".org") ||
				strings.Contains(part, ".net") || strings.Contains(part, ".io") ||
				strings.Contains(part, ".dev") {

				// Clean up the domain string
				domain := part
				// Remove common prefixes
				if strings.HasPrefix(domain, "http://") {
					domain = strings.TrimPrefix(domain, "http://")
				}
				if strings.HasPrefix(domain, "https://") {
					domain = strings.TrimPrefix(domain, "https://")
				}
				// Remove paths and query parameters
				if strings.Contains(domain, "/") {
					domain = strings.Split(domain, "/")[0]
				}

				cmd.Domain = domain
				e.logger.Infof("Extracted domain from command: %s", cmd.Domain)
				break
			}
		}
	}

	// If domain is still empty, generate a fallback name based on command hash
	if cmd.Domain == "" {
		cmdHash := models.HashFile([]byte(cmd.Raw))
		shortHash := cmdHash[:8]
		if cmd.CommandType != "" {
			cmd.Domain = fmt.Sprintf("unknown_%s_%s", cmd.CommandType, shortHash)
		} else {
			cmd.Domain = fmt.Sprintf("unknown_cmd_%s", shortHash)
		}
		e.logger.Warnf("Could not extract domain, using fallback name: %s", cmd.Domain)
	}

	// Execute command using bash with the raw command string
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

	// Capture stdout always
	stdoutBytes := stdout.Bytes()

	// Try to read the output file if specified in the command
	var output []byte
	if cmd.OutputFile != "" {
		// Wait a moment to ensure file system has completed writing
		time.Sleep(100 * time.Millisecond)

		output, err = os.ReadFile(cmd.OutputFile)
		if err != nil {
			e.logger.Warnf("Could not read specified output file %s: %v", cmd.OutputFile, err)
			// Use stdout as fallback
			output = stdoutBytes
		} else {
			e.logger.Debugf("Successfully read specified output file: %s (%d bytes)", cmd.OutputFile, len(output))
		}
	} else {
		// If no output file specified in command, use stdout
		output = stdoutBytes
	}

	// Ensure output is not empty
	if len(output) == 0 {
		e.logger.Warnf("Command produced empty output, using stdout as fallback")
		output = stdoutBytes
	}

	result.Output = output

	// Calculate hash of the output
	result.OutputHash = models.HashFile(result.Output)
	e.logger.Debugf("Output hash: %s", result.OutputHash)

	// Save result to the structured storage if file manager is available
	if e.fileManager != nil {
		// Ensure we have a scan type
		if cmd.ScanType == "" {
			cmd.DetermineScanType()
		}

		storagePath, err := e.fileManager.SaveScanResult(
			cmd.Domain,
			cmd.CommandType,
			cmd.ScanType,
			cmd.Raw,
			output,
		)

		if err != nil {
			e.logger.Errorf("Failed to save scan result to structured storage: %v", err)
		} else {
			e.logger.Infof("Saved scan result to structured storage: %s", storagePath)
			result.StoragePath = storagePath

			// Try to retrieve the previous scan result for comparison
			prevScan, err := e.fileManager.GetPreviousScanResult(cmd.Domain, cmd.CommandType, cmd.ScanType)
			if err == nil && prevScan != nil {
				// Get the previous scan timestamp for reference
				cmd.LastRun = prevScan.Timestamp

				// Check if the output has changed by comparing with the latest.json
				latestScan, err := e.fileManager.GetLatestScanResult(cmd.Domain, cmd.CommandType, cmd.ScanType)
				if err == nil && latestScan != nil {
					// Check if there are differences
					rawPrev, _ := json.Marshal(prevScan.Output)
					rawLatest, _ := json.Marshal(latestScan.Output)

					if string(rawPrev) != string(rawLatest) {
						result.HasChanged = true
						e.logger.Infof("Changes detected for command: %s", cmd.Raw)

						// Set previous output for reference
						prevOutputStr := ""
						if prevScan.RawOutput != "" {
							prevOutputStr = prevScan.RawOutput
						} else {
							prevOutputBytes, _ := json.MarshalIndent(prevScan.Output, "", "  ")
							prevOutputStr = string(prevOutputBytes)
						}

						cmd.LastOutput = []byte(prevOutputStr)

						// Get the diff from the diff.json file
						timestampDir := filepath.Dir(storagePath)
						diffPath := filepath.Join(timestampDir, "diff.json")
						diffData, err := os.ReadFile(diffPath)
						if err == nil {
							var diffResult filemanager.DiffResult
							if err := json.Unmarshal(diffData, &diffResult); err == nil && diffResult.DiffSummary != "" {
								result.Differences = diffResult.DiffSummary
							} else {
								// Fallback to simple text diff
								result.Differences = fmt.Sprintf("Changes detected. Check diff at: %s", diffPath)
							}
						} else {
							result.Differences = "Changes detected but diff not found"
						}

						// Display differences in terminal
						fmt.Println("\n=== Changes Detected ===")
						fmt.Printf("Command: %s\n", cmd.Raw)
						fmt.Printf("Domain: %s (%s)\n", cmd.Domain, cmd.CommandType)
						fmt.Printf("Time: %s\n", time.Now().Format("2006-01-02 15:04:05"))
						fmt.Println("\nDifferences:")
						fmt.Println(result.Differences)
						fmt.Println("=====================\n")
					} else {
						e.logger.Debugf("No changes detected for command: %s", cmd.Raw)
					}
				}
			} else {
				e.logger.Debugf("No previous scan found for comparison: %v", err)

				// For first run, still mark it as changed to trigger notifications
				if len(result.Output) > 0 {
					result.HasChanged = true
					result.Differences = "Initial run - no previous data to compare with"
					e.logger.Infof("First run for command: %s", cmd.Raw)
				}
			}
		}
	} else {
		e.logger.Warnf("File manager not available, skipping structured storage")
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

	// Track total commands for completion
	totalCommands := len(commands)
	processedCommands := 0
	resultsChan := make(chan *models.CommandResult, totalCommands)

	// Create a wait group to track all goroutines
	var wg sync.WaitGroup

	// Send commands to the queue with parallel execution control
	for _, cmdGroup := range urlGroups {
		for _, cmd := range cmdGroup {
			wg.Add(1)
			go func(cmd *models.Command) {
				defer wg.Done()

				// Acquire a slot
				select {
				case parallelChan <- struct{}{}:
					// Slot acquired, continue
				case <-ctx.Done():
					e.logger.Warn("Context cancelled while waiting for slot")
					return
				}

				// Execute the command
				result := e.ExecuteCommand(ctx, cmd)

				// Process result
				resultsChan <- result

				// Release the slot
				<-parallelChan
			}(cmd)
		}
	}

	// Start a goroutine to close results channel when all commands are processed
	go func() {
		wg.Wait()
		close(resultsChan)
		e.logger.Info("All commands have been processed, finalizing results")
	}()

	// Collect results
	var results []*models.CommandResult
	for result := range resultsChan {
		results = append(results, result)
		processedCommands++
		e.logger.Infof("Processed %d/%d commands", processedCommands, totalCommands)
	}

	e.logger.Infof("Execution completed. Processed %d/%d commands", processedCommands, totalCommands)
	return results
}
