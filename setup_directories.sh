#!/bin/bash
# Setup script for INN2 filter directory structure
# Run this script to create all required directories for the spam filter

echo "Creating INN2 filter directory structure..."

# Core directories for filter operation
mkdir -p /news/spam/log /news/spam/data /news/spam/bin /news/spam/posted

# NNRPD filter working directories
mkdir -p /news/spam/nnrpd/check
mkdir -p /news/spam/nnrpd/found
mkdir -p /news/spam/nnrpd/php_user_rates

# Set appropriate permissions
chmod 700 /news/ || echo "Warning: chmod failed"

# Make directories writable by the news server process
chown -R news:news /news/spam 2>/dev/null || echo "Warning: Could not change ownership to news:news (run as root if needed)"
