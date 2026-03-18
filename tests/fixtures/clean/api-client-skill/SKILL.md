---
name: api-client
description: Make HTTP API requests with structured output
version: "3.2.1"
metadata:
  openclaw:
    requires:
      env:
        - API_BASE_URL
      bins:
        - curl
    emoji: "🌐"
    install:
      - id: jq
        kind: brew
        formula: jq
        bins:
          - jq
        label: jq (JSON processor)
---

# API Client

Make HTTP requests to REST APIs and get structured JSON responses.

## Usage

Ask the agent:
- "GET https://api.example.com/users"
- "POST to /api/items with body {name: 'test'}"
- "Show me the response headers from the last request"

## Features

- Supports GET, POST, PUT, PATCH, DELETE methods
- Automatic JSON formatting with jq
- Request history tracking
- Response header inspection
- Cookie management for session-based APIs

## Configuration

Set your `API_BASE_URL` environment variable to the default API endpoint:

```bash
export API_BASE_URL=https://api.example.com
```

## Examples

### Simple GET Request

```
> GET /users/1
{
  "id": 1,
  "name": "John Doe",
  "email": "john@example.com"
}
```

### POST with Body

```
> POST /users {"name": "Jane", "role": "admin"}
201 Created
{
  "id": 2,
  "name": "Jane",
  "role": "admin"
}
```
