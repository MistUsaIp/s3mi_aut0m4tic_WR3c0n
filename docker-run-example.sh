#!/bin/bash

# Build the Docker image
docker build -t watchtower .

# Run the application with Docker
docker run -v $(pwd)/samples:/data \
  watchtower \
  --ffuf-cmds=/data/ffuf_commands.txt \
  --x8-cmds=/data/x8_commands.txt \
  --discord-webhook=https://discord.com/api/webhooks/your-webhook-url \
  --interval=30m \
  --mode=MR \
  --verbose 