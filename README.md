# Agentic AI Security Testing

Standard security scanners don't know what to do with LLM applications. They can't test for prompt injection, system prompt leakage, or an AI agent that decides to email your entire user base when asked nicely. This tool is built specifically for that gap.

It runs automated security probes against LLM-powered applications and scores them against the OWASP Top 10 for LLMs 2025. Each OWASP category is a separate module with curated payloads and detection logic — you can add your own or extend the existing ones.

The platform deploys on ECS Fargate with a FastAPI backend and a simple React frontend for browsing results. I built it to run security assessments during CI on our internal AI tools — catching prompt injection issues before they reach production is a lot cheaper than dealing with them after.

## What it tests

| OWASP ID | Category | What we probe for |
|----------|----------|-------------------|
| LLM01 | Prompt Injection | Can the model be hijacked by adversarial input? |
| LLM06 | Excessive Agency | Will the model execute harmful actions when asked? |
| LLM07 | System Prompt Leakage | Can we extract the system prompt through clever questioning? |
| LLM02 | Sensitive Info Leakage | Does the model reveal training data or PII? |
| LLM10 | Unbounded Consumption | Can we trigger DoS through resource-exhausting prompts? |

## Architecture

```
GitHub Actions
  └── trigger scan on PR

FastAPI (ECS Fargate, private subnet)
  ├── POST /api/scan        — submit a target URL for scanning
  ├── GET  /api/results/:id — get scan results
  └── WebSocket /api/live   — real-time progress during a scan

React frontend (ECS Fargate, public subnet via ALB)
  └── submits scans, shows findings with severity + explanation

RDS PostgreSQL
  └── stores scan history and results

S3
  └── full scan reports as JSON
```

## Running a scan

```bash
# Against a local LLM API
python -m src.agents.owasp_llm_scanner \
  --target http://localhost:8080/api/chat \
  --api-key your-key \
  --output report.json

# Via the REST API
curl -X POST http://your-deployment/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://your-llm-app/chat", "categories": ["LLM01", "LLM07"]}'
```

## Adding custom payloads

Each category module has a `payloads` list. Add your own:

```python
# In src/payloads/custom_injection.py
PAYLOADS = [
    "Your custom prompt injection attempt",
    "Another test payload",
]
```

Then register it in `src/agents/owasp_llm_scanner.py` under the relevant category.

## CI integration

```yaml
# In your GitHub Actions pipeline
- name: LLM Security Scan
  run: |
    python -m src.agents.owasp_llm_scanner \
      --target ${{ secrets.STAGING_LLM_URL }} \
      --fail-on-critical
```

`--fail-on-critical` exits non-zero if any critical vulnerabilities are found, blocking the PR merge.

## Deploying

```bash
cd terraform
terraform init && terraform apply

# Build and push the scanner image
docker build -t llm-security-scanner .
docker tag llm-security-scanner $ECR_URI/llm-security-scanner:latest
docker push $ECR_URI/llm-security-scanner:latest
```
