package filemanager

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

	// Find added and removed lines
	addedLines := []string{}
	removedLines := []string{}

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

	// Find removed lines
	for _, line := range oldLines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !newMap[line] {
			removedLines = append(removedLines, line)
		}
	}

	// Find added lines
	for _, line := range newLines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !oldMap[line] {
			addedLines = append(addedLines, line)
		}
	}

	// Build the difference summary
	var diffBuilder strings.Builder

	if len(addedLines) > 0 {
		diffBuilder.WriteString("Added lines:\n")
		for i, line := range addedLines {
			if i < 10 { // Limit to first 10 lines for readability
				diffBuilder.WriteString(fmt.Sprintf("+ %s\n", line))
			} else {
				diffBuilder.WriteString(fmt.Sprintf("... and %d more added lines\n", len(addedLines)-10))
				break
			}
		}
	}

	if len(removedLines) > 0 {
		if diffBuilder.Len() > 0 {
			diffBuilder.WriteString("\n")
		}
		diffBuilder.WriteString("Removed lines:\n")
		for i, line := range removedLines {
			if i < 10 { // Limit to first 10 lines for readability
				diffBuilder.WriteString(fmt.Sprintf("- %s\n", line))
			} else {
				diffBuilder.WriteString(fmt.Sprintf("... and %d more removed lines\n", len(removedLines)-10))
				break
			}
		}
	}

	if diffBuilder.Len() == 0 {
		return "Changes detected but exact differences couldn't be determined"
	}

	return diffBuilder.String()
}

// calculateJSONDiff calculates differences between JSON objects
func calculateJSONDiff(oldScan, newScan ScanResult) DiffResult {
	diffResult := DiffResult{
		PreviousScan: oldScan.Timestamp,
		CurrentScan:  newScan.Timestamp,
		HasChanges:   false,
	}

	// This is a simplified version - in a real implementation,
	// you would do a more thorough comparison of the JSON structures

	// Get string representations of both outputs for simple comparison
	oldJSON, _ := json.Marshal(oldScan.Output)
	newJSON, _ := json.Marshal(newScan.Output)

	if string(oldJSON) != string(newJSON) {
		diffResult.HasChanges = true

		// In a real implementation, you would parse the JSON and compare
		// the structures more intelligently to identify added, modified, and
		// removed items. For now, we'll just note that changes were detected.
		diffResult.DiffSummary = "Changes detected in JSON structure. Detailed comparison not implemented yet."
	}

	return diffResult
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
