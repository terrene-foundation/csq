#!/bin/bash
# Deployment script v1 -- identical in source and target
set -euo pipefail

echo "Deploying governance-api..."

# Run migrations
python manage.py migrate

# Collect static files
python manage.py collectstatic --no-input

# Restart services
systemctl restart governance-api
systemctl restart governance-worker

echo "Deployment complete."
