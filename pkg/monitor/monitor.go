package monitor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/avanguard/watchtower/pkg/executor"
	"github.com/avanguard/watchtower/pkg/models"
	"github.com/avanguard/watchtower/pkg/notifier"
	"github.com/sirupsen/logrus"
)

// Monitor handles periodic command execution and monitoring
type Monitor struct {
	executor     *executor.CommandExecutor
	notifier     *notifier.DiscordNotifier
	logger       *logrus.Logger
	interval     time.Duration
	ffufCommands []*models.Command
	x8Commands   []*models.Command
	stopChan     chan struct{}
	mode         string
	monitoring   bool
}

// MonitorOptions contains configuration options for the Monitor
type MonitorOptions struct {
	FFufCommandsFile string
	X8CommandsFile   string
	DiscordWebhook   string
	Interval         time.Duration
	Mode             string
	Monitoring       bool
}

// NewMonitor creates a new Monitor instance
func NewMonitor(opts MonitorOptions, logger *logrus.Logger) (*Monitor, error) {
	// Initialize the executor
	execInst := executor.NewCommandExecutor(logger)

	// Initialize the notifier
	var notifyInst *notifier.DiscordNotifier
	if opts.DiscordWebhook != "" {
		notifyInst = notifier.NewDiscordNotifier(opts.DiscordWebhook, logger)
	}

	m := &Monitor{
		executor:   execInst,
		notifier:   notifyInst,
		logger:     logger,
		interval:   opts.Interval,
		stopChan:   make(chan struct{}),
		mode:       opts.Mode,
		monitoring: opts.Monitoring,
	}

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

	// Start the command execution ticker
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	m.logger.Infof("Starting WatchTower monitor in %s mode, checking every %v", m.mode, m.interval)
	m.logger.Infof("Loaded %d ffuf commands and %d x8 commands", len(m.ffufCommands), len(m.x8Commands))

	// Immediately run the first iteration before waiting for the ticker
	go m.executeCommands()

	for {
		select {
		case <-ticker.C:
			go m.executeCommands()
		case <-sigChan:
			m.logger.Info("Received termination signal, shutting down...")
			close(m.stopChan)
			return
		case <-m.stopChan:
			return
		}
	}
}

// Stop halts the monitoring process
func (m *Monitor) Stop() {
	close(m.stopChan)
}

// executeCommands runs all the commands and handles notifications
func (m *Monitor) executeCommands() {
	m.logger.Info("Starting command execution cycle")

	ctx, cancel := context.WithTimeout(context.Background(), m.interval-5*time.Second)
	defer cancel()

	// Combine all commands
	allCommands := append(m.ffufCommands, m.x8Commands...)

	// If monitoring is enabled, open separate terminals for each command
	if m.monitoring {
		// Create a channel to control parallel execution
		parallelChan := make(chan struct{}, 5) // Allow 5 parallel executions

		for _, cmd := range allCommands {
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

echo "=== Monitoring Command ==="
echo "Command: %s"
echo "Started at: $(date)"
echo "========================"

while true; do
    echo "Running command at: $(date)"
    echo "------------------------"
    %s
    echo "------------------------"
    echo "Command completed at: $(date)"
    echo "========================"
    echo "Waiting %d seconds until next run..."
    sleep %d
done`, cmd.Raw, cmd.Raw, int(m.interval.Seconds()), int(m.interval.Seconds()))

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

	// Process results and send notifications for changes
	for _, result := range results {
		if result.HasChanged || result.Error != nil {
			if m.notifier != nil {
				err := m.notifier.SendAlert(result)
				if err != nil {
					m.logger.Errorf("Failed to send notification: %v", err)
				}
			}
		}

		// Log the result
		m.logger.Info(result.String())
	}

	m.logger.Info("Finished command execution cycle")
}
