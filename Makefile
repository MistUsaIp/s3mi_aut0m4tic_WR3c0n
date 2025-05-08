.PHONY: build run clean test

# Application name
APP_NAME=watchtower

# Go flags
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Build flags
LDFLAGS=-ldflags "-w -s"

all: build

# Build the application
build:
	$(GOBUILD) $(LDFLAGS) -o $(APP_NAME) cmd/watchtower/main.go

# Install dependencies
deps:
	$(GOMOD) tidy

# Run the application
run: build
	./$(APP_NAME)

# Run unit tests
test:
	$(GOTEST) -v ./...

# Clean build artifacts
clean:
	$(GOCLEAN)
	rm -f $(APP_NAME)

# Build a small docker image
docker:
	docker build -t $(APP_NAME):latest .

# Sample targets for testing
create-samples:
	@echo "Creating sample command files for testing..."
	@mkdir -p samples
	@echo "ffuf -u https://example.com/FUZZ -w wordlist -o example_f.out" > samples/ffuf_cmds.txt
	@echo "ffuf -u https://test.com/FUZZ -w wordlist -o test_f.out" >> samples/ffuf_cmds.txt
	@echo "x8 -u https://example.com/client -w wordlist -X GET POST -o example_p.out" > samples/x8_cmds.txt
	@echo "Sample files created in the samples directory."

# Run with sample files
run-with-samples: build create-samples
	./$(APP_NAME) --ffuf-cmds=samples/ffuf_cmds.txt --x8-cmds=samples/x8_cmds.txt --interval=1m --verbose 