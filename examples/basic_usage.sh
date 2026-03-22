#!/bin/bash
# Basic vaos-kernel usage example

BASE_URL=${1:-http://localhost:8080}

echo "=== Health Check ==="
curl -s $BASE_URL/health
echo

echo "=== List Agents ==="
curl -s $BASE_URL/api/agents | python3 -m json.tool
echo

echo "=== Issue Token (agent: zoe, action: read-users) ==="
curl -s -X POST $BASE_URL/api/token \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "zoe",
    "intent_hash": "read-table-users-query-all",
    "action_type": "query"
  }' | python3 -m json.tool
echo

echo "=== Issue Token (agent: osa, action: send-email) ==="
curl -s -X POST $BASE_URL/api/token \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "osa",
    "intent_hash": "send-email-to-team-status-update",
    "action_type": "notify"
  }' | python3 -m json.tool
