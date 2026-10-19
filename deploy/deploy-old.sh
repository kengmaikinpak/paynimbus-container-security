#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# deploy-old.sh — Bob's deployment script (DO NOT USE AS-IS)
# -----------------------------------------------------------------------------
# This is what the previous engineer was using to ship to Cloud Run. It is
# kept here as a reference for "what not to do". Almost every line below
# violates at least one of the requirements in the mini-project brief.
# -----------------------------------------------------------------------------

set -e

PROJECT_ID="paynimbus-prod"
REGION="us-central1"                     # Why not asia-southeast1? Who knows.
IMAGE="gcr.io/$PROJECT_ID/history-api"   # Public-ish GCR, not Artifact Registry

# Build locally. No multi-stage, no scanning, no signing.
docker build -t "$IMAGE:latest" .

# Push to the legacy gcr.io registry
docker push "$IMAGE:latest"

# Deploy to Cloud Run with everything wide open
gcloud run deploy history-api \
    --image="$IMAGE:latest" \
    --region="$REGION" \
    --platform=managed \
    --allow-unauthenticated \
    --service-account="deployer@paynimbus-prod.iam.gserviceaccount.com" \
    --set-env-vars="STRIPE_API_KEY=sk_live_REALKEY_DONT_LEAK,DB_PASSWORD=hunter2" \
    --port=5000

# The service account above has roles/editor on the project. Bob says
# "we'll lock it down later". Later never came.

echo "Deployed. Probably."
