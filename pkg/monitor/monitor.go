package monitor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
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
		close(m.stopChan) // Ensure monitor stops if no commands
		return
	}

	m.logger.Infof("Preparing to execute %d commands", totalCommands)

	// Create the main output directory if it doesn't exist
	if err := os.MkdirAll("res_files", 0755); err != nil {
		m.logger.Errorf("Failed to create main output directory: %v", err)
		// Not returning here, executor might still work if dir exists or command doesn't write files
	}

	// If monitoring is enabled, open separate terminals for each command's output
	if m.monitoring {
		// Create a channel to control parallel execution of tailing terminals
		parallelChan := make(chan struct{}, m.threads)

		m.logger.Infof("Monitoring mode enabled: Launching terminals to tail output files for %d commands.", totalCommands)

		for _, cmd := range allCommands {
			// Get the output file path that the executor will use (via GetModifiedCommand logic implicitly)
			// The fileManager will save output based on domain/type/scanType.
			// For tailing, we need the path GetModifiedCommand would use.
			// Let's ensure domain and command type are determined for GetOutputFilePaths
			if cmd.CommandType == "" {
				cmd.DetermineCommandType()
			}
			if cmd.Domain == "" { // Attempt to extract domain if not already set
				cmd.ExtractURL() // This also calls ExtractDomain
				if cmd.Domain == "" {
					// Fallback logic similar to executor if still no domain
					cmdParts := strings.Split(cmd.Raw, " ")
					for _, part := range cmdParts {
						if strings.Contains(part, ".com") || strings.Contains(part, ".org") ||
							strings.Contains(part, ".net") || strings.Contains(part, ".io") ||
							strings.Contains(part, ".dev") {
							domain := strings.TrimPrefix(strings.TrimPrefix(part, "https://"), "http://")
							if strings.Contains(domain, "/") {
								domain = strings.Split(domain, "/")[0]
							}
							cmd.Domain = domain
							break
					}
				}
					if cmd.Domain == "" { // If still no domain, use a placeholder for path generation
						m.logger.Warnf("Cannot determine domain for command '%s' for tailing, output path might be unpredictable.", cmd.Raw)
						// We can't easily replicate the hash-based fallback domain name from executor here
						// So, we might skip tailing for this command or use a very generic path if GetOutputFilePaths handles empty domain.
						// For now, let GetOutputFilePaths decide.
					}
				}
			}

			// This is the file path that GetModifiedCommand directs output to.
			// The actual execution by CommandExecutor will use this path if it parses the modified command.
			// Or, if the command has its own -o, CommandExecutor uses that, then FileManager saves to its structured path.
			// For tailing, we *must* use the path defined by GetModifiedCommand, as that's what the script *would* have used.
			// However, the actual output will be in fileManager's structured path.
			// This reveals a slight disconnect. The monitoring script was based on GetModifiedCommand's output.
			// The CommandExecutor will save to a structured path.
			// For robust tailing, we should tail the fileManager's *actual* output file for this specific execution.
			// This means we need to know the *future* timestamped path *before* execution. This is not feasible.

			// Let's reconsider: The CommandExecutor saves output.
			// If a command has "-o output.txt", executor reads output.txt. FileManager saves its content.
			// If ffuf has no "-o", GetModifiedCommand would add "-o <domain>_F/..._new.txt".
			// The original monitoring script *ran* GetModifiedCommand.
			// Now, the CommandExecutor runs cmd.Raw.
			// So we should tail the file specified in cmd.OutputFile if present,
			// otherwise, we can't easily tail a generic stdout that isn't being redirected by the raw command.

			// New strategy:
			// 1. The CommandExecutor will eventually save the output to a structured path (e.g., .../timestamp/raw.json).
			// 2. We can't tail this easily predictively.
			// 3. If the *original* command specified an output file (`cmd.OutputFile`), we can tail that.
			// 4. If not, tailing is difficult. We might just log verbosely for those.

			// Simpler approach for monitoring: Tail the file that GetModifiedCommand *would* create.
			// This assumes the user understands that if they use -monitoring, their command *will be modified*
			// to output to this standard location, and the executor should run this *modified* command.
			// This requires changing ExecuteCommand to run cmd.GetModifiedCommand() if monitoring is on.
			// OR, the monitor prepares the modified command and passes *that* to the executor.

			// Let's stick to: if monitoring, the commands submitted to executor *are* the modified commands.
			// This ensures output files are standardized and tail-able.

			modifiedCmdStr := cmd.GetModifiedCommand() // This command will be executed
			tailFilePath := cmd.OutputFile // GetOutputFilePaths() gives _new.txt, _old.txt. cmd.OutputFile is now set by GetModifiedCommand logic

			// Need to re-parse OutputFile from the modified command string, as GetModifiedCommand sets it.
			// Create a temporary command object to parse the output file from the modified command
			tempCmdForPath := models.NewCommand(modifiedCmdStr)
			tailFilePath = tempCmdForPath.OutputFile

			if tailFilePath == "" {
				m.logger.Warnf("Command '%s' (modified: '%s') does not specify an output file, cannot tail for monitoring.", cmd.Raw, modifiedCmdStr)
				continue
			}

			// Ensure the directory for the tailFilePath exists, as tail -f needs the file (or for dir to exist for file creation)
			if err := os.MkdirAll(filepath.Dir(tailFilePath), 0755); err != nil {
				m.logger.Warnf("Could not create directory for tail file %s: %v", tailFilePath, err)
				// continue // Might still work if command creates it
			}


			domainDisplay := cmd.Domain
			if domainDisplay == "" {
				domainDisplay = "unknown"
			}

			// Create a monitoring script for this command
			scriptContent := fmt.Sprintf(`#!/bin/bash
# Keep the terminal open
set -e

# Function to clean up on exit
cleanup() {
    echo "Monitoring stopped for: %s"
    echo "Output was being tailed from: %s"
    echo "Terminal will close in 10 seconds..."
    # Keep the window open for 10 seconds before closing
    sleep 10
}

# Set up trap for cleanup
trap cleanup EXIT SIGINT SIGTERM

echo "=== Monitoring Output ==="
echo "Original Command: %s"
echo "Executed Command: %s"
echo "Tailing output file: %s"
echo "Domain: %s (%s)"
echo "Started at: $(date)"
echo "========================="
echo "Waiting for output file to appear/update..."
echo "(If this window is blank for a long time, the command might not be producing output to this file, or it might have finished quickly)"
echo "========================="

# Wait for the file to exist, then tail it
while [ ! -f "%s" ]; do sleep 1; done
tail -f -n 50 "%s"
`, cmd.Raw, tailFilePath, cmd.Raw, modifiedCmdStr, tailFilePath, domainDisplay, cmd.CommandType, tailFilePath, tailFilePath)

			// Create a temporary script file
			scriptFile := fmt.Sprintf("/tmp/watchtower_tail_%d.sh", time.Now().UnixNano())
			if err := os.WriteFile(scriptFile, []byte(scriptContent), 0755); err != nil {
				m.logger.Errorf("Failed to create monitoring script for tailing: %v", err)
				continue
			}

			// Wait for a slot in the parallel execution channel
			parallelChan <- struct{}{}

			// Open a new terminal window with the monitoring script
			// Try gnome-terminal, then xterm
			var termCmd *exec.Cmd
			termPath, err := exec.LookPath("gnome-terminal")
			if err == nil {
				termCmd = exec.Command(termPath, "--", "bash", "-c", fmt.Sprintf("bash %s; exec bash", scriptFile))
			} else {
				xtermPath, err := exec.LookPath("xterm")
				if err == nil {
					termCmd = exec.Command(xtermPath, "-e", "bash", "-c", fmt.Sprintf("bash %s; exec bash", scriptFile))
				} else {
					m.logger.Error("No suitable terminal found (gnome-terminal or xterm) for monitoring.")
					os.Remove(scriptFile)
					<-parallelChan // Release slot
					continue
				}
			}

			if err := termCmd.Start(); err != nil {
				m.logger.Errorf("Failed to open monitoring terminal for tailing: %v", err)
				os.Remove(scriptFile)
				<-parallelChan // Release the slot
				continue
			}
			m.logger.Infof("Launched terminal for tailing output of: %s (file: %s)", cmd.Raw, tailFilePath)

			// Clean up the script file after a delay
			go func(sf string) {
				time.Sleep(5 * time.Second) // Give terminal time to load script
				os.Remove(sf)
			}(scriptFile)

			// Release the parallel execution slot
			go func() {
				// No sleep needed here, as Start() is non-blocking.
				// The number of concurrent terminals is managed by parallelChan buffer.
				<-parallelChan
			}()
		}
		// Modify allCommands to be their GetModifiedCommand version
		// so the executor runs the version that produces tail-able files.
		for i := range allCommands {
			// Create a new command object based on the modified string for execution
			// This ensures that the OutputFile field is correctly parsed from the modified command
			allCommands[i] = models.NewCommand(allCommands[i].GetModifiedCommand())
		}
		m.logger.Info("All commands have been modified for output redirection in monitoring mode.")
	}

	// Execute commands via the executor - THIS NOW ALWAYS RUNS
	// If monitoring is enabled, allCommands will be the modified versions.
	m.logger.Infof("Submitting %d commands to executor...", len(allCommands))
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

	// Signal that all commands are done if stopChan is not already closed
	select {
	case <-m.stopChan:
		// Already closing or closed
	default:
		m.logger.Info("All commands have been processed. Signalling monitor to stop.")
	close(m.stopChan)
	}
}
