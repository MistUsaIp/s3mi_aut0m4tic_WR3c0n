package main

import (
	"flag"
	"runtime"

	"github.com/avanguard/watchtower/pkg/monitor"
	"github.com/sirupsen/logrus"
)

func main() {
	// Set maximum number of OS threads for parallelism (use 70% of available CPUs)
	numCPU := runtime.NumCPU()
	maxProcs := int(float64(numCPU) * 0.7)
	if maxProcs < 1 {
		maxProcs = 1 // Ensure at least one CPU is used
	}
	runtime.GOMAXPROCS(maxProcs)

	// Parse command line arguments
	ffufCmdsFile := flag.String("ffuf-cmds", "", "Path to file containing ffuf commands")
	x8CmdsFile := flag.String("x8-cmds", "", "Path to file containing x8 commands")
	discordWebhook := flag.String("discord-webhook", "", "Discord webhook URL for notifications")
	mode := flag.String("mode", "MR", "Operating mode (currently only MR mode is supported)")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	monitoring := flag.Bool("monitoring", false, "Open separate terminal windows for each command's execution details")
	threads := flag.Int("thread", 5, "Number of commands to execute in parallel")
	flag.IntVar(threads, "t", 5, "Number of commands to execute in parallel (shorthand)")
	flag.Parse()

	// Set up logging
	logger := logrus.New()
	if *verbose {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}

	// Log CPU usage
	logger.Infof("Using %d/%d CPU cores (70%% of available cores)", maxProcs, numCPU)

	// Validate required arguments
	if *ffufCmdsFile == "" && *x8CmdsFile == "" {
		logger.Fatal("At least one of --ffuf-cmds or --x8-cmds must be specified")
	}

	// Validate thread count
	if *threads < 1 {
		logger.Fatal("Thread count must be at least 1")
	}

	// Create monitor options
	opts := monitor.MonitorOptions{
		FFufCommandsFile: *ffufCmdsFile,
		X8CommandsFile:   *x8CmdsFile,
		DiscordWebhook:   *discordWebhook,
		Mode:             *mode,
		Monitoring:       *monitoring,
		Threads:          *threads,
	}

	// Create and start the monitor
	m, err := monitor.NewMonitor(opts, logger)
	if err != nil {
		logger.Fatalf("Failed to create monitor: %v", err)
	}

	// Start the monitor
	m.Start()
}
