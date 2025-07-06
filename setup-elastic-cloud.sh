#!/bin/bash

# Elastic Cloud on Kubernetes - Credential Setup
# This script just sets your Elastic Cloud credentials as environment variables
# The actual deployment is handled by deploy.sh

# Set your Elastic Cloud credentials here
export ELASTIC_CLOUD_URL="https://798a3a233ea341aaad5b6c044a95fb25.us-central1.gcp.cloud.es.io:443"
export ELASTIC_CLOUD_API_KEY="SlFaVHpKY0JBTWFEMkZxbWNqNUQ6YXB4THhlYklFc0tod3R5OFBaMG05Zw=="

echo "✅ Elastic Cloud credentials loaded"
echo "   URL: $ELASTIC_CLOUD_URL"
echo "   API Key: ${ELASTIC_CLOUD_API_KEY:0:20}..."
echo ""
echo "🚀 Run deployment commands:"
echo "   ./deploy.sh --elastic-cloud --all                    # Everything with Elastic Cloud"
echo "   ./deploy.sh --elastic-cloud --monitoring             # Just monitoring"
echo "   ./deploy.sh --all                                    # Self-hosted ELK stack"