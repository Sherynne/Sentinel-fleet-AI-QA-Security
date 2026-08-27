#!/bin/bash
# Sentinel Fleet — Cloud Run Deployment Script
# Deploys 4 JarvisCore agents to Google Cloud Run

set -e

# Configuration
PROJECT_ID=${1:-""}
REGION=${2:-"us-central1"}
REDIS_URL=${REDIS_URL:-""}
CLAUDE_API_KEY=${CLAUDE_API_KEY:-""}

if [ -z "$PROJECT_ID" ]; then
    echo "Usage: ./deploy.sh <project-id> [region]"
    echo "Ensure CLAUDE_API_KEY and REDIS_URL are exported in your environment."
    exit 1
fi

if [ -z "$CLAUDE_API_KEY" ] || [ -z "$REDIS_URL" ]; then
    echo "❌ ERROR: CLAUDE_API_KEY and REDIS_URL must be exported."
    echo "Example:"
    echo "export CLAUDE_API_KEY=sk-ant-..."
    echo "export REDIS_URL=rediss://default:pwd@host:6379"
    exit 1
fi

echo "🚀 Deploying Sentinel Fleet to $PROJECT_ID ($REGION)"

gcloud config set project "$PROJECT_ID"

# Enable required APIs
echo "📦 Enabling Cloud Run and Cloud Build APIs..."
gcloud services enable run.googleapis.com cloudbuild.googleapis.com

# Deploy services independently
deploy_service() {
    local NAME=$1
    local DIR=$2
    local PORT=$3
    
    echo "🚢 Deploying $NAME..."
    
    # We build the image locally and deploy to ensure it picks up the root context properly
    gcloud run deploy "$NAME" \
        --source . \
        --region "$REGION" \
        --port "$PORT" \
        --allow-unauthenticated \
        --set-env-vars="CLAUDE_API_KEY=$CLAUDE_API_KEY,REDIS_URL=$REDIS_URL" \
        --quiet \
        --format="value(status.url)"
}

# In JarvisCore Cloud Run deployments, we don't necessarily need seed nodes 
# if they all talk to the same Redis instance for discovery and queues.
# The `Mesh` will use Redis for P2P transport automatically when REDIS_URL is present.

# 1. Explorer (Agent 2)
EXPLORER_URL=$(deploy_service "sentinel-explorer" "services/explorer" 8001)
echo "✅ Explorer deployed: $EXPLORER_URL"

# 2. QA Tester (Agent 3)
QA_URL=$(deploy_service "sentinel-qa" "services/qa" 8002)
echo "✅ QA Tester deployed: $QA_URL"

# 3. Security Analyst (Agent 4)
SECURITY_URL=$(deploy_service "sentinel-security" "services/security" 8003)
echo "✅ Security Analyst deployed: $SECURITY_URL"

# 4. Orchestrator (Agent 1)
# Pass the orchestrator URL to itself so it knows its public address for report links
ORCHESTRATOR_URL=$(deploy_service "sentinel-orchestrator" "services/orchestrator" 8000)

echo "🎉 Deployment Complete!"
echo "---------------------------------------------------"
echo "🛡️ Sentinel Fleet Dashboard & API:"
echo "👉 $ORCHESTRATOR_URL"
echo "---------------------------------------------------"
echo "To run a scan:"
echo "curl -X POST $ORCHESTRATOR_URL/scan \\"
echo "  -H \"Content-Type: application/json\" \\"
echo "  -d '{\"target_url\": \"https://jsonplaceholder.typicode.com\"}'"
