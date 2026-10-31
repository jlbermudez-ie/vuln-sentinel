# Tech stack — orders-api

Human-readable summary of what this service runs on. The fenced `techstack`
block below is machine-readable: **vuln-sentinel** parses it to match CVEs.
Keep versions exact — the scanner compares them against NVD version ranges.

- **Service:** orders-api (critical, customer-facing)
- **Owner:** platform-team
- **Exposure:** Internet → ALB (HTTP/HTTPS) → AWS Lambda
- **Runtime:** PHP on Lambda via Bref 3 layer in FPM mode (ALB event → PHP-FPM)

```techstack
service: orders-api
kind: code
criticality: critical
components:
  - name: php
    vendor: php
    product: php
    version: "8.3.30"          # pinned by the Bref layer version in orders-infra
    role: language-runtime
  - name: bref
    vendor: bref
    product: bref
    version: "3.0"
    role: lambda-runtime-layer
  - name: aws-lambda
    vendor: amazon
    product: aws_lambda
    version: "provided.al2023"
    role: compute
```

## Remediation constraints

See `.remediation.yml`. This service is under a **change freeze**: code or
runtime changes need a full regression cycle (~4 weeks). Automated code fixes
are disabled; mitigations must happen at the infrastructure layer.
