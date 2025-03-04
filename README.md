# one-united

A lightweight API gateway for large language models (LLMs) built on [Cloudflare Workers](https://workers.cloudflare.com), designed to simplify interactions with multiple LLM providers by exposing an one-united OpenAI-compatible endpoint.

## Overview

- 🦀 **Language & Tools:** Built with [worker-rs](https://github.com/cloudflare/workers-rs) and deployed using [Wrangler](https://developers.cloudflare.com/workers/wrangler).
- ⭐ **Key Features:**
  - 🤖 Easily deploy your own LLM API gateway.
  - ☁️ Benefit from the Cloudflare infrastructure.
  - 🔄 One unified endpoint for multiple LLM providers with a latency-based load-balancing strategy.
  - 🔑 OpenAI-compatible API.
- 🚧 **TODO:**
  - [ ] Provide more customizable load balancing configuration.
  - [ ] Intuitive front-end configuration management interface

## Deployment

Before deploying, ensure that you have the following installed:

- A recent version of [Rust](https://rustup.rs)
- [npm](https://docs.npmjs.com/downloading-and-installing-node-js-and-npm)

### 1. Clone and Setup the Repository

Clone the repository and copy the example Wrangler configuration:

```bash
git clone https://github.com/one-united/one-united.git
cp wrangler.example.toml wrangler.toml
```

### 2. Create a KV Namespace

The worker uses a Cloudflare KV namespace to store its configuration. [Create a KV namespace](https://developers.cloudflare.com/workers/wrangler/commands/#kv-namespace-create) with:

```bash
npx wrangler kv:namespace create config
```

After running the command above, copy the provided `kv_namespaces` section and paste it into your `wrangler.toml` file. It should appear similar to:

```toml
[[kv_namespaces]]
binding = "config"
id = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

### 3. Deploy the Worker

Then, simply run the following command to deploy the worker:

```bash
npx wrangler deploy
```

Once deployed, your worker will be available at the URL:

```
https://<YOUR_WORKER>.<YOUR_SUBDOMAIN>.workers.dev
```

You can verify its status through [Cloudflare’s dashboard](https://dash.cloudflare.com).

### 4. Set Your API Secret (Optional but Recommended)

To secure your endpoint from unauthorized use, configure your API secret:

```bash
npx wrangler secret put ONE_API_KEY
```

## Usage

After deployment, you need to upload a configuration that defines your LLM providers and routing rules. Send a POST request to `/config` with your configuration. Edit the `config.example.json` file with your actual provider details and API keys.

```bash
mv config.example.json config.json && vim config.json
curl -X POST https://<YOUR_WORKER>.<YOUR_SUBDOMAIN>.workers.dev/config \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ONE_API_KEY" \
  -d @config.json
```

To check if the configuration has been successfully applied, use:

```bash
curl -H "Authorization: Bearer $ONE_API_KEY" -s https://<YOUR_WORKER>.<YOUR_SUBDOMAIN>.workers.dev/config
```

Once configured, you can now send chat completions requests via the unified endpoint. For example:

```bash
curl https://<YOUR_WORKER>.<YOUR_SUBDOMAIN>.workers.dev/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ONE_API_KEY" \
  -d '{
     "model": "gpt-4o",
     "messages": [{"role": "user", "content": "Say this is a test!"}],
     "temperature": 0.7
   }'
```

For more details on how to use the API and customize your requests, please refer to the [OpenAI API documentation](https://beta.openai.com/docs/api-reference/introduction).
