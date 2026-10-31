# Tech stack — orders-infra

Infrastructure for **orders-api**. vuln-sentinel reads the `techstack` block to
learn which controls exist and which files it is allowed to change.

```techstack
service: orders-infra
kind: infra
iac: terraform
cloud: aws
region_var: aws_region
serves: [orders-api]
components:
  - name: alb
    product: aws_application_load_balancer
    role: edge / L7 routing to Lambda
    file: terraform/alb.tf
  - name: aws-waf
    product: aws_wafv2_web_acl
    role: L7 filtering on the ALB (REGIONAL scope)
    file: terraform/waf.tf
    data_file: security/waf-rules.json   # rules are data; change this, not waf.tf
  - name: lambda
    product: aws_lambda_function
    role: runs orders-api
    file: terraform/lambda.tf
  - name: bref-php-layer
    product: php
    version: "8.3.30"
    role: PHP runtime layer for the Lambda (variable bref_php_layer_arn)
    file: terraform/variables.tf
mitigation_surfaces:
  - id: waf-managed-rule-group
    file: security/waf-rules.json
    path: managed_rule_groups
    allowed_values: [AWSManagedRulesCommonRuleSet, AWSManagedRulesKnownBadInputsRuleSet, AWSManagedRulesPHPRuleSet, AWSManagedRulesLinuxRuleSet, AWSManagedRulesSQLiRuleSet, AWSManagedRulesAmazonIpReputationList]
  - id: waf-custom-header-rule
    file: security/waf-rules.json
    path: custom_rules
  - id: waf-rate-limit
    file: security/waf-rules.json
    path: rate_limit
```

## Change rules for automation

- Bots may only edit `security/waf-rules.json`. Everything else needs a human.
- Every PR runs `terraform fmt/validate/plan` and a JSON-schema check.
- `main` is protected: 1 approving review + green plan before merge.
- Apply runs on merge to `main` in the `production` environment (manual approval).
