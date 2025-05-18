package filemanager

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

// FileManager handles structured storage of scan results
type FileManager struct {
	BaseDir string // Base directory for all results
}

// ScanResult represents the result of a command execution
type ScanResult struct {
	Command     string      `json:"command"`
	CommandType string      `json:"command_type"`
	Domain      string      `json:"domain"`
	ScanType    string      `json:"scan_type"`
	Timestamp   time.Time   `json:"timestamp"`
	Output      interface{} `json:"output"` // Can be parsed JSON or raw string
	RawOutput   string      `json:"raw_output,omitempty"`
}

// DiffResult represents differences between two scan results
type DiffResult struct {
	PreviousScan  time.Time                `json:"previous_scan"`
	CurrentScan   time.Time                `json:"current_scan"`
	HasChanges    bool                     `json:"has_changes"`
	AddedItems    []map[string]interface{} `json:"added_items,omitempty"`
	RemovedItems  []map[string]interface{} `json:"removed_items,omitempty"`
	ModifiedItems []map[string]interface{} `json:"modified_items,omitempty"`
	DiffSummary   string                   `json:"diff_summary,omitempty"`
}

// DomainMetadata stores information about a domain
type DomainMetadata struct {
	Domain      string     `json:"domain"`
	FirstSeen   time.Time  `json:"first_seen"`
	LastScan    time.Time  `json:"last_scan"`
	ScanCount   int        `json:"scan_count"`
	ToolsUsed   []string   `json:"tools_used"`
	ScanTypes   []string   `json:"scan_types"`
	ChangeCount int        `json:"change_count"`
	LastChanged *time.Time `json:"last_changed,omitempty"`
}

// NewFileManager creates a new file manager with the specified base directory
func NewFileManager(baseDir string) (*FileManager, error) {
	// Use "res_files" as default if not specified
	if baseDir == "" {
		baseDir = "res_files"
	}

	// Create the base directory if it doesn't exist
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create base directory: %v", err)
	}

	// Create the domains directory
	domainsDir := filepath.Join(baseDir, "domains")
	if err := os.MkdirAll(domainsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create domains directory: %v", err)
	}

	// Create the stats directory
	statsDir := filepath.Join(baseDir, "stats")
	if err := os.MkdirAll(statsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create stats directory: %v", err)
	}

	return &FileManager{
		BaseDir: baseDir,
	}, nil
}

// GetToolScanType determines the scan type based on command
func GetToolScanType(command, tool string) string {
	command = strings.ToLower(command)

	switch tool {
	case "ffuf":
		if strings.Contains(command, "wordlist") || strings.Contains(command, "-w") {
			if strings.Contains(command, "FUZZ") {
				return "endpoints"
			}
			if strings.Contains(command, "HOST") {
				return "subdomains"
			}
		}
	case "x8":
		if strings.Contains(command, "-X POST") || strings.Contains(command, "-X PUT") {
			return "parameters"
		}
		return "endpoints"
	}

	// Default scan type
	return "general"
}

// SaveScanResult stores a scan result in the structured directory format
func (fm *FileManager) SaveScanResult(domain, toolName, scanType string, cmdRaw string, output []byte) (string, error) {
	if domain == "" {
		return "", fmt.Errorf("domain cannot be empty")
	}

	// Clean domain name for file paths
	domain = strings.ReplaceAll(domain, ":", "_")

	// Determine scan type if not provided
	if scanType == "" {
		scanType = GetToolScanType(cmdRaw, toolName)
	}

	// Create timestamp for this scan
	now := time.Now()
	timestamp := now.Format("20060102-150405")

	// Create directory structure
	domainDir := filepath.Join(fm.BaseDir, "domains", domain)
	toolDir := filepath.Join(domainDir, toolName)
	scanTypeDir := filepath.Join(toolDir, scanType)
	timestampDir := filepath.Join(scanTypeDir, timestamp)

	// Create all necessary directories
	if err := os.MkdirAll(timestampDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create scan directory: %v", err)
	}

	// Parse the output as JSON if possible
	var outputJSON interface{}
	outputStr := string(output)
	err := json.Unmarshal(output, &outputJSON)
	isJSON := err == nil

	// Create scan result structure
	scanResult := ScanResult{
		Command:     cmdRaw,
		CommandType: toolName,
		Domain:      domain,
		ScanType:    scanType,
		Timestamp:   now,
	}

	if isJSON {
		scanResult.Output = outputJSON
	} else {
		scanResult.Output = "Raw output (non-JSON)"
		scanResult.RawOutput = outputStr
	}

	// Marshal the scan result to JSON
	resultJSON, err := json.MarshalIndent(scanResult, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal scan result: %v", err)
	}

	// Save raw scan output
	rawFilePath := filepath.Join(timestampDir, "raw.json")
	if err := os.WriteFile(rawFilePath, resultJSON, 0644); err != nil {
		return "", fmt.Errorf("failed to write raw scan result: %v", err)
	}

	// Create or update symbolic links
	latestLinkPath := filepath.Join(scanTypeDir, "latest.json")
	previousLinkPath := filepath.Join(scanTypeDir, "previous.json")

	// Check if latest.json exists
	_, err = os.Stat(latestLinkPath)
	if err == nil {
		// latest.json exists, move it to previous.json
		// In case previous.json exists, remove it first
		_ = os.Remove(previousLinkPath)

		// Read the latest.json to get its content
		latestContent, err := os.ReadFile(latestLinkPath)
		if err == nil {
			// Write content to previous.json
			if err := os.WriteFile(previousLinkPath, latestContent, 0644); err != nil {
				fmt.Printf("Warning: failed to update previous.json: %v\n", err)
			}
		}
	}

	// Update latest.json to point to new scan
	if err := os.WriteFile(latestLinkPath, resultJSON, 0644); err != nil {
		fmt.Printf("Warning: failed to update latest.json: %v\n", err)
	}

	// Check for previous scan and calculate differences
	if _, err := os.Stat(previousLinkPath); err == nil {
		fm.calculateAndSaveDiff(domain, toolName, scanType, previousLinkPath, rawFilePath, timestampDir)
	}

	// Update domain metadata
	fm.updateDomainMetadata(domain, toolName, scanType, now)

	return rawFilePath, nil
}

// calculateAndSaveDiff calculates differences between two scans and saves them
func (fm *FileManager) calculateAndSaveDiff(domain, toolName, scanType, previousPath, currentPath, timestampDir string) error {
	// Read previous and current scan results
	previousData, err := os.ReadFile(previousPath)
	if err != nil {
		return fmt.Errorf("failed to read previous scan: %v", err)
	}

	currentData, err := os.ReadFile(currentPath)
	if err != nil {
		return fmt.Errorf("failed to read current scan: %v", err)
	}

	// Parse scan results
	var previousScan ScanResult
	var currentScan ScanResult

	if err := json.Unmarshal(previousData, &previousScan); err != nil {
		return fmt.Errorf("failed to parse previous scan: %v", err)
	}

	if err := json.Unmarshal(currentData, &currentScan); err != nil {
		return fmt.Errorf("failed to parse current scan: %v", err)
	}

	// Initialize diff result
	diffResult := DiffResult{
		PreviousScan: previousScan.Timestamp,
		CurrentScan:  currentScan.Timestamp,
		HasChanges:   false,
	}

	// Calculate differences based on output format
	if previousScan.RawOutput != "" || currentScan.RawOutput != "" {
		// Text-based comparison for non-JSON outputs
		if previousScan.RawOutput != currentScan.RawOutput {
			diffResult.HasChanges = true
			diffResult.DiffSummary = calculateTextDiff(previousScan.RawOutput, currentScan.RawOutput)
		}
	} else {
		// JSON-based comparison
		diffResult = calculateJSONDiff(previousScan, currentScan)
	}

	// Save diff result
	diffFilePath := filepath.Join(timestampDir, "diff.json")
	diffJSON, err := json.MarshalIndent(diffResult, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal diff result: %v", err)
	}

	if err := os.WriteFile(diffFilePath, diffJSON, 0644); err != nil {
		return fmt.Errorf("failed to write diff result: %v", err)
	}

	// If changes were detected, update domain metadata
	if diffResult.HasChanges {
		metadataPath := filepath.Join(fm.BaseDir, "domains", domain, "meta.json")
		var metadata DomainMetadata

		// Read existing metadata if available
		metadataBytes, err := os.ReadFile(metadataPath)
		if err == nil {
			_ = json.Unmarshal(metadataBytes, &metadata)
		}

		// Update change information
		metadata.ChangeCount++
		now := time.Now()
		metadata.LastChanged = &now

		// Save updated metadata
		updatedMetadata, _ := json.MarshalIndent(metadata, "", "  ")
		_ = os.WriteFile(metadataPath, updatedMetadata, 0644)
	}

	return nil
}

// updateDomainMetadata creates or updates metadata for a domain
func (fm *FileManager) updateDomainMetadata(domain, toolName, scanType string, scanTime time.Time) error {
	metadataPath := filepath.Join(fm.BaseDir, "domains", domain, "meta.json")

	// Initialize metadata
	metadata := DomainMetadata{
		Domain:    domain,
		FirstSeen: scanTime,
		LastScan:  scanTime,
		ScanCount: 1,
		ToolsUsed: []string{toolName},
		ScanTypes: []string{scanType},
	}

	// Check if metadata file already exists
	metadataBytes, err := os.ReadFile(metadataPath)
	if err == nil {
		// Parse existing metadata
		var existingMetadata DomainMetadata
		if err := json.Unmarshal(metadataBytes, &existingMetadata); err == nil {
			// Update fields
			metadata.FirstSeen = existingMetadata.FirstSeen
			metadata.ScanCount = existingMetadata.ScanCount + 1
			metadata.LastScan = scanTime
			metadata.ChangeCount = existingMetadata.ChangeCount
			metadata.LastChanged = existingMetadata.LastChanged

			// Update tools used
			toolExists := false
			for _, tool := range existingMetadata.ToolsUsed {
				if tool == toolName {
					toolExists = true
					break
				}
			}
			if !toolExists {
				metadata.ToolsUsed = append(existingMetadata.ToolsUsed, toolName)
			} else {
				metadata.ToolsUsed = existingMetadata.ToolsUsed
			}

			// Update scan types
			scanTypeExists := false
			for _, st := range existingMetadata.ScanTypes {
				if st == scanType {
					scanTypeExists = true
					break
				}
			}
			if !scanTypeExists {
				metadata.ScanTypes = append(existingMetadata.ScanTypes, scanType)
			} else {
				metadata.ScanTypes = existingMetadata.ScanTypes
			}
		}
	}

	// Marshal and save metadata
	updatedMetadata, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal domain metadata: %v", err)
	}

	if err := os.WriteFile(metadataPath, updatedMetadata, 0644); err != nil {
		return fmt.Errorf("failed to write domain metadata: %v", err)
	}

	return nil
}

// UpdateTargetsList adds a domain to the targets list if it's not already there
func (fm *FileManager) UpdateTargetsList(domain string) error {
	targetsPath := filepath.Join(fm.BaseDir, "targets.txt")

	// Read existing targets
	var targets []string
	targetsData, err := os.ReadFile(targetsPath)
	if err == nil {
		// Parse existing targets
		lines := strings.Split(string(targetsData), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" {
				targets = append(targets, line)
			}
		}
	}

	// Check if domain is already in targets
	for _, target := range targets {
		if target == domain {
			return nil // Domain already in list
		}
	}

	// Add domain to targets
	targets = append(targets, domain)

	// Write updated targets list
	targetsContent := strings.Join(targets, "\n") + "\n"
	if err := os.WriteFile(targetsPath, []byte(targetsContent), 0644); err != nil {
		return fmt.Errorf("failed to update targets list: %v", err)
	}

	return nil
}

// calculateTextDiff calculates differences between two text strings
func calculateTextDiff(oldText, newText string) string {
	// Split text into lines
	oldLines := strings.Split(oldText, "\n")
	newLines := strings.Split(newText, "\n")

	// Remove any trailing empty lines
	for len(oldLines) > 0 && strings.TrimSpace(oldLines[len(oldLines)-1]) == "" {
		oldLines = oldLines[:len(oldLines)-1]
	}
	for len(newLines) > 0 && strings.TrimSpace(newLines[len(newLines)-1]) == "" {
		newLines = newLines[:len(newLines)-1]
	}

	// Find added, removed, and unchanged lines
	addedLines := []string{}
	removedLines := []string{}
	unchangedLines := []string{}

	// Create maps for faster lookup
	oldMap := make(map[string]int) // Line -> position
	newMap := make(map[string]int)

	// Index all lines by content for quick lookup
	for i, line := range oldLines {
		if strings.TrimSpace(line) != "" {
			oldMap[line] = i
		}
	}

	for i, line := range newLines {
		if strings.TrimSpace(line) != "" {
			newMap[line] = i
		}
	}

	// Find removed lines
	for _, line := range oldLines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if _, exists := newMap[line]; !exists {
			removedLines = append(removedLines, line)
		} else {
			unchangedLines = append(unchangedLines, line)
		}
	}

	// Find added lines
	for _, line := range newLines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if _, exists := oldMap[line]; !exists {
			addedLines = append(addedLines, line)
		}
	}

	// Build the difference summary with context
	var diffBuilder strings.Builder

	// Add a header summarizing the changes
	if len(addedLines) > 0 || len(removedLines) > 0 {
		diffBuilder.WriteString(fmt.Sprintf("# Summary: %d line(s) added, %d line(s) removed\n\n", 
			len(addedLines), len(removedLines)))
	} else {
		diffBuilder.WriteString("# Changes detected but no line additions/removals found\n")
		diffBuilder.WriteString("# (Possible changes in formatting or whitespace)\n\n")
	}

	// Add removed lines with context
	if len(removedLines) > 0 {
		diffBuilder.WriteString("# Lines removed:\n")
		for i, line := range removedLines {
			if i < 15 { // Limit to first 15 lines for readability
				// Try to find context (unchanged lines around this one)
				linePos := oldMap[line]
				
				// Add a bit of context if possible
				if linePos > 0 && linePos < len(oldLines)-1 {
					contextBefore := oldLines[linePos-1]
					if strings.TrimSpace(contextBefore) != "" && !containsLine(removedLines, contextBefore) {
						diffBuilder.WriteString(fmt.Sprintf("  %s\n", contextBefore))
					}
				}
				
				diffBuilder.WriteString(fmt.Sprintf("- %s\n", line))
				
				// Add context after if possible
				if linePos < len(oldLines)-1 {
					contextAfter := oldLines[linePos+1]
					if strings.TrimSpace(contextAfter) != "" && !containsLine(removedLines, contextAfter) {
						diffBuilder.WriteString(fmt.Sprintf("  %s\n", contextAfter))
					}
				}
				diffBuilder.WriteString("\n")
			} else {
				diffBuilder.WriteString(fmt.Sprintf("... and %d more removed lines\n\n", len(removedLines)-15))
				break
			}
		}
	}

	// Add added lines with context
	if len(addedLines) > 0 {
		if len(removedLines) > 0 {
			diffBuilder.WriteString("\n")
		}
		diffBuilder.WriteString("# Lines added:\n")
		for i, line := range addedLines {
			if i < 15 { // Limit to first 15 lines for readability
				// Try to find context (unchanged lines around this one)
				linePos := newMap[line]
				
				// Add a bit of context if possible
				if linePos > 0 {
					contextBefore := newLines[linePos-1]
					if strings.TrimSpace(contextBefore) != "" && !containsLine(addedLines, contextBefore) {
						diffBuilder.WriteString(fmt.Sprintf("  %s\n", contextBefore))
					}
				}
				
				diffBuilder.WriteString(fmt.Sprintf("+ %s\n", line))
				
				// Add context after if possible
				if linePos < len(newLines)-1 {
					contextAfter := newLines[linePos+1]
					if strings.TrimSpace(contextAfter) != "" && !containsLine(addedLines, contextAfter) {
						diffBuilder.WriteString(fmt.Sprintf("  %s\n", contextAfter))
					}
				}
				diffBuilder.WriteString("\n")
			} else {
				diffBuilder.WriteString(fmt.Sprintf("... and %d more added lines\n", len(addedLines)-15))
				break
			}
		}
	}

	if diffBuilder.Len() == 0 {
		return "Changes detected but exact differences couldn't be determined"
	}

	return diffBuilder.String()
}

// containsLine checks if a line exists in a slice of lines
func containsLine(lines []string, target string) bool {
	for _, line := range lines {
		if line == target {
			return true
		}
	}
	return false
}

// calculateJSONDiff calculates differences between JSON objects
func calculateJSONDiff(oldScan, newScan ScanResult) DiffResult {
	diffResult := DiffResult{
		PreviousScan: oldScan.Timestamp,
		CurrentScan:  newScan.Timestamp,
		HasChanges:   false,
		AddedItems:   make([]map[string]interface{}, 0),
		RemovedItems: make([]map[string]interface{}, 0),
		ModifiedItems: make([]map[string]interface{}, 0),
	}

	// Get JSON representations
	oldJSON, oldErr := json.Marshal(oldScan.Output)
	newJSON, newErr := json.Marshal(newScan.Output)

	// If we can't parse either as JSON, fall back to text comparison
	if oldErr != nil || newErr != nil {
		if string(oldJSON) != string(newJSON) {
			diffResult.HasChanges = true
			diffResult.DiffSummary = fmt.Sprintf("JSON parsing error, doing simple text comparison: %v / %v", 
				oldErr, newErr)
			return diffResult
		}
	}

	if string(oldJSON) == string(newJSON) {
		// No changes detected
		return diffResult
	}

	// We have changes
	diffResult.HasChanges = true

	// Try to unmarshal both into comparable data structures
	var oldData, newData interface{}
	json.Unmarshal(oldJSON, &oldData)
	json.Unmarshal(newJSON, &newData)

	// Build a human-readable diff summary
	var diffBuilder strings.Builder
	
	diffBuilder.WriteString("# JSON Difference Summary\n\n")

	// Case 1: Both are objects (maps)
	oldMap, oldIsMap := oldData.(map[string]interface{})
	newMap, newIsMap := newData.(map[string]interface{})

	if oldIsMap && newIsMap {
		// Track what we've found
		keysFound := make(map[string]bool)
		
		// Check for added and modified keys
		diffBuilder.WriteString("## Object comparison\n\n")
		
		// First check for added and modified keys
		for key, newVal := range newMap {
			keysFound[key] = true
			oldVal, exists := oldMap[key]
			
			if !exists {
				// Added key
				addedItem := map[string]interface{}{
					"key": key,
					"value": truncateJSONValue(newVal),
				}
				diffResult.AddedItems = append(diffResult.AddedItems, addedItem)
				diffBuilder.WriteString(fmt.Sprintf("+ Added key: `%s` = `%s`\n", key, truncateJSONValue(newVal)))
			} else if !reflect.DeepEqual(oldVal, newVal) {
				// Modified key
				modifiedItem := map[string]interface{}{
					"key": key,
					"old_value": truncateJSONValue(oldVal),
					"new_value": truncateJSONValue(newVal),
				}
				diffResult.ModifiedItems = append(diffResult.ModifiedItems, modifiedItem)
				diffBuilder.WriteString(fmt.Sprintf("* Modified key: `%s`\n", key))
				diffBuilder.WriteString(fmt.Sprintf("  - Old: `%s`\n", truncateJSONValue(oldVal)))
				diffBuilder.WriteString(fmt.Sprintf("  + New: `%s`\n", truncateJSONValue(newVal)))
			}
		}
		
		// Then check for removed keys
		for key, oldVal := range oldMap {
			if !keysFound[key] {
				// Removed key
				removedItem := map[string]interface{}{
					"key": key,
					"value": truncateJSONValue(oldVal),
				}
				diffResult.RemovedItems = append(diffResult.RemovedItems, removedItem)
				diffBuilder.WriteString(fmt.Sprintf("- Removed key: `%s` = `%s`\n", key, truncateJSONValue(oldVal)))
			}
		}
	} else if oldArr, oldIsArr := oldData.([]interface{}); oldIsArr {
		newArr, newIsArr := newData.([]interface{})
		if newIsArr {
			// Case 2: Both are arrays
			diffBuilder.WriteString(fmt.Sprintf("## Array comparison\n\n"))
			diffBuilder.WriteString(fmt.Sprintf("* Array length: %d → %d\n\n", len(oldArr), len(newArr)))
			
			// Find common length for item-by-item comparison
			minLen := len(oldArr)
			if len(newArr) < minLen {
				minLen = len(newArr)
			}
			
			// Compare items that exist in both arrays
			for i := 0; i < minLen; i++ {
				if !reflect.DeepEqual(oldArr[i], newArr[i]) {
					diffBuilder.WriteString(fmt.Sprintf("* Modified at index %d:\n", i))
					diffBuilder.WriteString(fmt.Sprintf("  - Old: `%s`\n", truncateJSONValue(oldArr[i])))
					diffBuilder.WriteString(fmt.Sprintf("  + New: `%s`\n\n", truncateJSONValue(newArr[i])))
				}
			}
			
			// List added items
			if len(newArr) > len(oldArr) {
				diffBuilder.WriteString("# Added items:\n")
				for i := len(oldArr); i < len(newArr) && i < len(oldArr)+5; i++ {
					addedItem := map[string]interface{}{
						"index": i,
						"value": truncateJSONValue(newArr[i]),
					}
					diffResult.AddedItems = append(diffResult.AddedItems, addedItem)
					diffBuilder.WriteString(fmt.Sprintf("+ [%d]: `%s`\n", i, truncateJSONValue(newArr[i])))
				}
				if len(newArr) > len(oldArr)+5 {
					diffBuilder.WriteString(fmt.Sprintf("+ ... and %d more added items\n\n", len(newArr)-len(oldArr)-5))
				}
			}
			
			// List removed items
			if len(oldArr) > len(newArr) {
				diffBuilder.WriteString("# Removed items:\n")
				for i := len(newArr); i < len(oldArr) && i < len(newArr)+5; i++ {
					removedItem := map[string]interface{}{
						"index": i,
						"value": truncateJSONValue(oldArr[i]),
					}
					diffResult.RemovedItems = append(diffResult.RemovedItems, removedItem)
					diffBuilder.WriteString(fmt.Sprintf("- [%d]: `%s`\n", i, truncateJSONValue(oldArr[i])))
				}
				if len(oldArr) > len(newArr)+5 {
					diffBuilder.WriteString(fmt.Sprintf("- ... and %d more removed items\n\n", len(oldArr)-len(newArr)-5))
				}
			}
		} else {
			// Case 3: Types don't match (array vs non-array)
			diffBuilder.WriteString("## Type change\n")
			diffBuilder.WriteString(fmt.Sprintf("* Changed from array to %T\n", newData))
		}
	} else {
		// Case 4: Simple values or incomparable types
		diffBuilder.WriteString("## Value change\n")
		diffBuilder.WriteString(fmt.Sprintf("- Old value: `%s`\n", truncateString(fmt.Sprintf("%v", oldData), 150)))
		diffBuilder.WriteString(fmt.Sprintf("+ New value: `%s`\n", truncateString(fmt.Sprintf("%v", newData), 150)))
	}

	// Save the diff summary
	if diffBuilder.Len() > 0 {
		diffResult.DiffSummary = diffBuilder.String()
	} else {
		diffResult.DiffSummary = "Changes detected but couldn't be analyzed in detail"
	}

	return diffResult
}

// truncateJSONValue returns a human-readable string for a JSON value, truncating if needed
func truncateJSONValue(val interface{}) string {
	switch v := val.(type) {
	case string:
		return truncateString(v, 100)
	case []interface{}:
		if len(v) > 3 {
			return fmt.Sprintf("array[%d items]", len(v))
		}
		bytes, _ := json.Marshal(v)
		str := string(bytes)
		return truncateString(str, 100)
	case map[string]interface{}:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		if len(keys) > 3 {
			return fmt.Sprintf("object{%d keys}", len(keys))
		}
		bytes, _ := json.Marshal(v)
		str := string(bytes)
		return truncateString(str, 100)
	default:
		return truncateString(fmt.Sprintf("%v", v), 100)
	}
}

// truncateString cuts a string to the max length and adds ellipsis if needed
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// GetPreviousScanResult retrieves the previous scan result for a domain
func (fm *FileManager) GetPreviousScanResult(domain, toolName, scanType string) (*ScanResult, error) {
	previousPath := filepath.Join(fm.BaseDir, "domains", domain, toolName, scanType, "previous.json")

	// Check if previous scan exists
	if _, err := os.Stat(previousPath); err != nil {
		return nil, fmt.Errorf("no previous scan found: %v", err)
	}

	// Read previous scan
	previousData, err := os.ReadFile(previousPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read previous scan: %v", err)
	}

	// Parse scan result
	var scanResult ScanResult
	if err := json.Unmarshal(previousData, &scanResult); err != nil {
		return nil, fmt.Errorf("failed to parse previous scan: %v", err)
	}

	return &scanResult, nil
}

// GetLatestScanResult retrieves the latest scan result for a domain
func (fm *FileManager) GetLatestScanResult(domain, toolName, scanType string) (*ScanResult, error) {
	latestPath := filepath.Join(fm.BaseDir, "domains", domain, toolName, scanType, "latest.json")

	// Check if latest scan exists
	if _, err := os.Stat(latestPath); err != nil {
		return nil, fmt.Errorf("no latest scan found: %v", err)
	}

	// Read latest scan
	latestData, err := os.ReadFile(latestPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read latest scan: %v", err)
	}

	// Parse scan result
	var scanResult ScanResult
	if err := json.Unmarshal(latestData, &scanResult); err != nil {
		return nil, fmt.Errorf("failed to parse latest scan: %v", err)
	}

	return &scanResult, nil
}
