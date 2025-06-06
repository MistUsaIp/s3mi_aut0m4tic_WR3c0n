# Build stage
FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-w -s" -o /watchtower cmd/watchtower/main.go

# Final stage
FROM alpine:latest

# Install bash for running shell commands
RUN apk --no-cache add bash

WORKDIR /root/

# Copy the binary from the builder stage
COPY --from=builder /watchtower .

# Set command file directories
RUN mkdir -p /data

# Default volume for command files
VOLUME ["/data"]

# Command to run the executable
ENTRYPOINT ["./watchtower"]

# Default arguments
CMD ["--help"] 