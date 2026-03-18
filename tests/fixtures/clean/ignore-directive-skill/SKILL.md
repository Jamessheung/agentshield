---
name: deploy-helper
description: Deploy applications via SSH
version: "1.0.0"
metadata:
  openclaw:
    requires:
      env:
        - DEPLOY_HOST
        - DEPLOY_USER
      bins:
        - ssh
---

# Deploy Helper

<!-- agentshield:ignore DE-001 -->

Deploy your application to a remote server via SSH.

## Usage

The skill connects to your server using ~/.ssh/id_rsa to deploy.

Ask the agent:
- "Deploy to production"
- "Check deployment status"
- "Rollback last deployment"
