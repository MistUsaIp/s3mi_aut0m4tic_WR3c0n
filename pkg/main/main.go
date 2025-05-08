package main

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/avanguard/watchtower/pkg/monitor"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	ffufCommandsFile string
	x8CommandsFile   string
	discordWebhook   string
	interval         time.Duration
	mode             string
	verbose          bool
	monitoring       bool
)

func initLogger() *logrus.Logger {
	logger := logrus.New()
	logger.SetOutput(os.Stdout)

	if verbose {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}

	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
	})

	return logger
}

func main() {
	// Set maximum number of OS threads for parallelism
	numCPU := runtime.NumCPU()
	runtime.GOMAXPROCS(numCPU)

	rootCmd := &cobra.Command{
		Use:   "watchtower",
		Short: "WatchTower - A tool for periodic monitoring of recon commands",
		Long: `WatchTower is a CLI tool that runs reconnaissance commands at regular intervals,
monitors their output for changes, and sends alerts when changes are detected.`,
		Run: func(cmd *cobra.Command, args []string) {
			logger := initLogger()

			logger.Infof("Running with maximum parallelism: %d OS threads", numCPU)

			// Check if required flags are provided
			if ffufCommandsFile == "" && x8CommandsFile == "" {
				logger.Fatal("At least one command file (--ffuf-cmds or --x8-cmds) must be provided")
			}

			// Create monitor options
			opts := monitor.MonitorOptions{
				FFufCommandsFile: ffufCommandsFile,
				X8CommandsFile:   x8CommandsFile,
				DiscordWebhook:   discordWebhook,
				Interval:         interval,
				Mode:             mode,
				Monitoring:       monitoring,
			}

			// Initialize the monitor
			monitorInst, err := monitor.NewMonitor(opts, logger)
			if err != nil {
				logger.Fatalf("Failed to initialize monitor: %v", err)
			}

			// Start monitoring
			monitorInst.Start()
		},
	}

	// Define flags
	rootCmd.Flags().StringVar(&ffufCommandsFile, "ffuf-cmds", "", "Path to file containing ffuf commands")
	rootCmd.Flags().StringVar(&x8CommandsFile, "x8-cmds", "", "Path to file containing x8 commands")
	rootCmd.Flags().StringVar(&discordWebhook, "discord-webhook", "", "Discord webhook URL for notifications")
	rootCmd.Flags().DurationVar(&interval, "interval", 30*time.Minute, "Interval between command executions")
	rootCmd.Flags().StringVar(&mode, "mode", "MR", "Operating mode (currently only MR mode is supported)")
	rootCmd.Flags().BoolVar(&verbose, "verbose", false, "Enable verbose logging")
	rootCmd.Flags().BoolVar(&monitoring, "monitoring", false, "Open separate terminal windows for each command's execution details")

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
