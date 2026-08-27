# Setting up Upstash Redis (Free Tier)

JarvisCore uses Redis for agent discovery, P2P communication, and durable workflow state.
For this Cloud Run deployment, the easiest and cheapest option is Serverless Redis from Upstash.

1. Go to [https://console.upstash.com/](https://console.upstash.com/) and sign in (GitHub/Google).
2. Click **Create Database**.
3. Name: `sentinel-redis`
4. Type: **Global** or **Regional** (Match your GCP region, e.g., US-Central).
5. Enable **TLS (SSL)**.
6. Click **Create**.
7. Scroll down to the **Redis Connect** section.
8. Click the **Python** tab, or look for the URL format.
9. Copy the `rediss://` URL (it includes the default user, password, and port).

Export it in your terminal before running `deploy.sh`:

```bash
export REDIS_URL="rediss://default:YOUR_PASSWORD@your-endpoint.upstash.io:6379"
```
