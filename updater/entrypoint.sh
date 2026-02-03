#!/bin/bash
set -e

echo "YARMCP Updater starting..."
echo "Schedule: ${UPDATE_SCHEDULE}"
echo "Repos path: ${REPOS_PATH}"
echo "Config path: ${CONFIG_PATH}"

# Create crontab file
echo "${UPDATE_SCHEDULE} /app/update.sh" > /tmp/crontab

# Run initial update on startup
echo "Running initial repository sync..."
/app/update.sh

# Start supercronic with the crontab
echo "Starting scheduled updates..."
exec supercronic /tmp/crontab
