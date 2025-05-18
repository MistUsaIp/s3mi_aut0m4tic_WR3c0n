#!/bin/bash

echo "Creating test changes for WatchTower change detection..."

# 1. Add new findings to x8 endpoint scan
X8_DIR="res_files/domains/a-root-servers-org.gslb.verisign.com/health/x8/endpoints"
X8_LATEST="$X8_DIR/latest.json"
X8_BACKUP="$X8_DIR/latest.json.bak"

# Make backup of original file
cp "$X8_LATEST" "$X8_BACKUP"

# Add new test endpoint finding
cat > "$X8_LATEST" << 'JSONEOF'
{
  "timestamp": "2023-05-18T20:36:26Z",
  "scan_type": "endpoints",
  "findings": [
    {
      "url": "https://a-root-servers-org.gslb.verisign.com/health/status",
      "status_code": 200,
      "content_type": "application/json",
      "response_time": 0.354
    },
    {
      "url": "https://a-root-servers-org.gslb.verisign.com/health/metrics",
      "status_code": 200,
      "content_type": "application/json", 
      "response_time": 0.289
    },
    {
      "url": "https://a-root-servers-org.gslb.verisign.com/health/admin",
      "status_code": 403,
      "content_type": "text/html",
      "response_time": 0.213,
      "note": "NEW FINDING - ADDED FOR TESTING"
    }
  ],
  "total_count": 3
}
JSONEOF

# 2. Modify ffuf scan results
FFUF_DIR="res_files/domains/onsitecrl.verisign.com/FUZZ/ffuf/general"
FFUF_LATEST="$FFUF_DIR/latest.json"
FFUF_BACKUP="$FFUF_DIR/latest.json.bak"

# Make backup of original file
cp "$FFUF_LATEST" "$FFUF_BACKUP"

# Create modified file (changed status code for an existing endpoint)
cat > "$FFUF_LATEST" << 'JSONEOF'
{
  "timestamp": "2023-05-18T21:44:17Z",
  "scan_type": "general",
  "findings": [
    {
      "url": "https://onsitecrl.verisign.com/robots.txt",
      "status_code": 200,
      "content_length": 423,
      "response_time": 0.254
    },
    {
      "url": "https://onsitecrl.verisign.com/sitemap.xml",
      "status_code": 404,
      "content_length": 156,
      "response_time": 0.187,
      "note": "CHANGED - Status was 200 before"
    },
    {
      "url": "https://onsitecrl.verisign.com/favicon.ico",
      "status_code": 200,
      "content_length": 1150,
      "response_time": 0.176
    }
  ],
  "total_count": 3
}
JSONEOF

# 3. Delete a finding from another file
DEL_DIR="res_files/domains/a-root-servers-org.gslb.verisign.com/FUZZ/ffuf/general"
DEL_LATEST="$DEL_DIR/latest.json"
DEL_BACKUP="$DEL_DIR/latest.json.bak"

# Make backup of original file
cp "$DEL_LATEST" "$DEL_BACKUP"

# Create file with one finding removed
cat > "$DEL_LATEST" << 'JSONEOF'
{
  "timestamp": "2023-05-18T20:36:10Z",
  "scan_type": "general",
  "findings": [
    {
      "url": "https://a-root-servers-org.gslb.verisign.com/robots.txt",
      "status_code": 200,
      "content_length": 423,
      "response_time": 0.254
    }
  ],
  "total_count": 1,
  "note": "One endpoint was removed for testing deletion detection"
}
JSONEOF

echo "Test changes created. Original files backed up with .bak extension."
echo "Run WatchTower now to test change detection." 