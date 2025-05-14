package monitor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/avanguard/watchtower/pkg/executor"
	"github.com/avanguard/watchtower/pkg/models"
	"github.com/avanguard/watchtower/pkg/notifier"
	"github.com/sirupsen/logrus"
)

// Monitor handles command execution and monitoring
type Monitor struct {
	executor          *executor.CommandExecutor
	notifier          *notifier.DiscordNotifier
	logger            *logrus.Logger
	ffufCommands      []*models.Command
	x8Commands        []*models.Command
	stopChan          chan struct{}
	mode              string
	monitoring        bool
	threads           int
	statusChan        chan struct{}
	mu                sync.Mutex
	completedCommands int
	remainingCommands int
}

// MonitorOptions contains configuration options for the Monitor
type MonitorOptions struct {
	FFufCommandsFile string
	X8CommandsFile   string
	DiscordWebhook   string
	Mode             string
	Monitoring       bool
	Threads          int
}

// NewMonitor creates a new Monitor instance
func NewMonitor(opts MonitorOptions, logger *logrus.Logger) (*Monitor, error) {
	// Initialize the executor with specified number of threads
	execInst := executor.NewCommandExecutor(logger, opts.Threads)

	// Initialize the notifier
	var notifyInst *notifier.DiscordNotifier
	if opts.DiscordWebhook != "" {
		notifyInst = notifier.NewDiscordNotifier(opts.DiscordWebhook, logger)
	}

	m := &Monitor{
		executor:   execInst,
		notifier:   notifyInst,
		logger:     logger,
		stopChan:   make(chan struct{}),
		mode:       opts.Mode,
		monitoring: opts.Monitoring,
		threads:    opts.Threads,
		statusChan: make(chan struct{}, 100), // Buffer for status update signals
	}

	// Set the callback to be notified when commands complete
	execInst.SetCommandDoneCallback(m.signalCommandCompletion)

	// Load commands from files
	if opts.FFufCommandsFile != "" {
		ffufCmds, err := loadCommandsFromFile(opts.FFufCommandsFile)
		if err != nil {
			return nil, err
		}
		m.ffufCommands = ffufCmds
	}

	if opts.X8CommandsFile != "" {
		x8Cmds, err := loadCommandsFromFile(opts.X8CommandsFile)
		if err != nil {
			return nil, err
		}
		m.x8Commands = x8Cmds
	}

	// Initialize command counters
	m.remainingCommands = len(m.ffufCommands) + len(m.x8Commands)

	return m, nil
}

// loadCommandsFromFile reads command strings from a file and converts them to Command objects
func loadCommandsFromFile(filePath string) ([]*models.Command, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	var commands []*models.Command

	for _, line := range lines {
		// Skip empty lines
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		commands = append(commands, models.NewCommand(line))
	}

	return commands, nil
}

// Start begins the monitoring process
func (m *Monitor) Start() {
	// Set up a signal handler to gracefully handle termination
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	m.logger.Infof("Starting WatchTower monitor in %s mode with %d parallel threads", m.mode, m.threads)
	m.logger.Infof("Loaded %d ffuf commands and %d x8 commands", len(m.ffufCommands), len(m.x8Commands))

	// Start status reporter
	go m.startStatusReporter()

	// Start continuous command execution
	go m.executeCommands()

	// Wait for termination signal
	select {
	case <-sigChan:
		m.logger.Info("Received termination signal, shutting down...")
		close(m.stopChan)
	case <-m.stopChan:
		return
	}
}

// startStatusReporter periodically reports the status of active commands
func (m *Monitor) startStatusReporter() {
	for {
		select {
		case <-m.statusChan:
			// Update and display status when a command completes
			m.mu.Lock()
			m.completedCommands++
			m.remainingCommands--
			activeCount := m.executor.GetActiveCommandCount()
			completed := m.completedCommands
			remaining := m.remainingCommands
			m.mu.Unlock()

			totalCommands := len(m.ffufCommands) + len(m.x8Commands)
			fmt.Printf("\n=== Command Execution Status ===\n")
			fmt.Printf("Active commands: %d/%d\n", activeCount, m.threads)
			fmt.Printf("Completed commands: %d\n", completed)
			fmt.Printf("Remaining commands: %d\n", remaining)
			fmt.Printf("Total commands: %d\n", totalCommands)
			fmt.Printf("Thread utilization: %.1f%%\n", float64(activeCount)/float64(m.threads)*100)
			fmt.Printf("Progress: %.1f%%\n", float64(completed)/float64(totalCommands)*100)
			fmt.Printf("==============================\n\n")
		case <-m.stopChan:
			return
		}
	}
}

// signalCommandCompletion notifies the status reporter that a command has completed
func (m *Monitor) signalCommandCompletion() {
	select {
	case m.statusChan <- struct{}{}:
		// Signal sent
	default:
		// Channel buffer is full, non-blocking
	}
}

// Stop halts the monitoring process
func (m *Monitor) Stop() {
	close(m.stopChan)
}

// executeCommands runs all the commands and handles notifications
func (m *Monitor) executeCommands() {
	m.logger.Info("Starting command execution cycle")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Combine all commands
	allCommands := append(m.ffufCommands, m.x8Commands...)
	totalCommands := len(allCommands)

	if totalCommands == 0 {
		m.logger.Warn("No commands to execute")
		return
	}

	m.logger.Infof("Preparing to execute %d commands", totalCommands)

	// Create the main output directory if it doesn't exist
	if err := os.MkdirAll("res_files", 0755); err != nil {
		m.logger.Errorf("Failed to create main output directory: %v", err)
	}

	// If monitoring is enabled, open separate terminals for each command
	if m.monitoring {
		// Create a channel to control parallel execution
		parallelChan := make(chan struct{}, m.threads) // Use specified number of threads

		for _, cmd := range allCommands {
			// Get the output file paths for monitoring
			newFilePath, _ := cmd.GetOutputFilePaths()
			domainDisplay := cmd.Domain
			if domainDisplay == "" {
				domainDisplay = "unknown"
			}

			// Create a monitoring script for this command
			scriptContent := fmt.Sprintf(`#!/bin/bash
# Keep the terminal open even if the command fails
set -e

# Function to clean up on exit
cleanup() {
    echo "Monitoring stopped at: $(date)"
    # Keep the window open for 5 seconds before closing
    sleep 5
}

# Set up trap for cleanup
trap cleanup EXIT

echo "=== Monitoring Command (%s - %s) ==="
echo "Command: %s"
echo "Output: %s"
echo "Started at: $(date)"
echo "========================"

while true; do
    echo "Running command at: $(date)"
    echo "------------------------"
    %s
    echo "------------------------"
    echo "Command completed at: $(date)"
    if [ -f "%s" ]; then
        echo "Output saved to: %s"
    fi
    echo "========================"
    # No sleep here - continuous execution
done`, cmd.CommandType, domainDisplay, cmd.Raw, newFilePath, cmd.GetModifiedCommand(), newFilePath, newFilePath)

			// Create a temporary script file
			scriptFile := fmt.Sprintf("/tmp/watchtower_monitor_%d.sh", time.Now().UnixNano())
			if err := os.WriteFile(scriptFile, []byte(scriptContent), 0755); err != nil {
				m.logger.Errorf("Failed to create monitoring script: %v", err)
				continue
			}

			// Wait for a slot in the parallel execution channel
			parallelChan <- struct{}{}

			// Open a new terminal window with the monitoring script
			monitorCmd := exec.Command("gnome-terminal", "--", "bash", "-c", fmt.Sprintf("bash %s; exec bash", scriptFile))
			if err := monitorCmd.Start(); err != nil {
				m.logger.Errorf("Failed to open monitoring terminal: %v", err)
				os.Remove(scriptFile)
				<-parallelChan // Release the slot
				continue
			}

			// Clean up the script file after a longer delay to ensure it's loaded
			go func(scriptFile string) {
				time.Sleep(5 * time.Second)
				os.Remove(scriptFile)
			}(scriptFile)

			// Release the parallel execution slot after a short delay
			go func() {
				time.Sleep(2 * time.Second)
				<-parallelChan
			}()
		}
	}

	// Execute commands in parallel, grouped by URL
	results := m.executor.ExecuteGroupedCommands(ctx, allCommands)
	m.logger.Infof("Received %d/%d results from command execution", len(results), totalCommands)

	// Process results and send notifications for changes
	for _, result := range results {
		// Send notifications for changes
		if result.HasChanged || result.Error != nil {
			if m.notifier != nil {
				err := m.notifier.SendAlert(result)
				if err != nil {
					m.logger.Errorf("Failed to send notification: %v", err)
				} else {
					m.logger.Infof("Sent notification for command: %s", result.Command.Raw)
				}
			}
		}

		// Log the result
		m.logger.Info(result.String())
	}

	m.logger.Info("Finished command execution cycle")

	// Signal that all commands are done
	m.logger.Info("All commands have been processed. Exiting.")
	close(m.stopChan)
}
