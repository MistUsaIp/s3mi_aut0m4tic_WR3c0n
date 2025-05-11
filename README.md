# WatchTower

WatchTower is a Golang CLI tool for periodic monitoring of reconnaissance commands. It executes commands at regular intervals, compares the outputs with previous results, and sends alerts when changes are detected.

## Features

- Concurrent execution of commands targeting different URLs
- Sequential execution of commands targeting the same URL to avoid conflicts
- Utilizes maximum OS threads for optimized parallel execution
- Periodic execution of commands at configurable intervals
- Comparison of new outputs with previous ones
- Shows detailed differences between outputs in Discord alerts
- Discord webhooks for alerting when changes are detected
- Modular design for easy extension
- Real-time monitoring in separate terminal windows for each command
- Automatic storage of result files in a dedicated directory

## Installation

```bash
# Clone the repository
git clone https://github.com/avanguard/watchtower.git
cd watchtower

# Build the application
go build -o watchtower cmd/watchtower/main.go

# Or install it directly
go install github.com/avanguard/watchtower/cmd/watchtower@latest
```

## Usage

WatchTower accepts two input files containing lists of commands to be executed:

```bash
./watchtower --ffuf-cmds=/path/to/ffuf_commands.txt --x8-cmds=/path/to/x8_commands.txt --discord-webhook=https://discord.com/api/webhooks/... --interval=30m
```

### Command Line Arguments

- `--ffuf-cmds`: Path to file containing ffuf commands
- `--x8-cmds`: Path to file containing x8 commands
- `--discord-webhook`: Discord webhook URL for notifications
- `--interval`: Interval between command executions (default: 30m)
- `--mode`: Operating mode (currently only MR mode is supported)
- `--verbose`: Enable verbose logging
- `--monitoring`: Open separate terminal windows for each command's execution details

### Example Command Files

**ffuf_commands.txt:**
```
ffuf -u https://site1.com/FUZZ -w wordlist -o site1_f.out
ffuf -u https://site2.com/FUZZ -w wordlist -o site2_f.out
ffuf -u https://site3.com/FUZZ -w wordlist -o site3_f.out
```

**x8_commands.txt:**
```
x8 -u https://site1.com/client -w wordlist -X GET POST -o site1_p.out
x8 -u https://site2.com/client -w wordlist -X GET POST -o site2_p.out
```

## How It Works

1. WatchTower reads the command files and extracts the URLs and output file paths
2. It groups commands by their target URLs to avoid concurrent execution of commands targeting the same URL
3. Commands are executed periodically at the specified interval
4. All output files are stored in the `res_files` directory for easy management
5. After each execution, the output is compared with the previous result
6. If changes are detected, an alert is sent to the specified Discord webhook with the detailed differences
7. When monitoring is enabled, each command runs in its own terminal window showing real-time execution details

## File Organization

- Command output files are automatically stored in the `res_files` directory
- The directory is created automatically if it doesn't exist
- Original filenames are preserved but stored in the centralized location
- This makes it easier to manage and track all output files in one place

## License

This project is licensed under the MIT License - see the LICENSE file for details. 