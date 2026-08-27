# Sentinel Fleet — AI QA Security Fleet

Sentinel Fleet is a 4-agent AI system built on **JarvisCore** that automatically maps, tests, and analyzes any API for functional defects and security vulnerabilities (OWASP API Top 10).

It is designed to be fully distributed and deployed as 4 independent Google Cloud Run microservices.

## Architecture

1. **OrchestratorAgent** (`:8000`) - FastAPI entrypoint, sequences workflow, generates HTML reports.
2. **APIExplorerAgent** (`:8001`) - Discovers API surface and attack vectors.
3. **QATesterAgent** (`:8002`) - Executes real HTTP requests testing edge cases, auth bypass, and validation.
4. **SecurityAnalystAgent** (`:8003`) - Analyzes results for security vulnerabilities and produces a CVSS-scored report.

State and peer-to-peer communication are handled via **Redis** (as per JarvisCore's durable architecture).

## Local Development

You need Docker installed.

1. `cp .env.example .env`
2. Add your `CLAUDE_API_KEY` to `.env`.
3. `docker-compose up -d --build`
4. Visit [http://localhost:8000](http://localhost:8000)

## Cloud Run Deployment

We use Upstash Redis (free tier) for the shared state, and Cloud Run for the agent execution.

### Prerequisites

1. A Google Cloud Project with Billing enabled.
2. `gcloud` CLI installed and authenticated.
3. An [Upstash Redis](https://upstash.com/) database (or GCP Cloud Memorystore).

### 1. Configure Upstash Redis

Read `setup_upstash.md` for 2-minute setup instructions. You will get a `REDIS_URL` that looks like `rediss://default:password@host:6379`.

### 2. Deploy

```bash
export CLAUDE_API_KEY="your-claude-api-key"
export REDIS_URL="rediss://default:your-upstash-password@your-upstash-host:6379"

chmod +x deploy.sh
./deploy.sh my-gcp-project-id us-central1
```

Once deployed, the script will output your public Orchestrator URL. Open it in your browser!
