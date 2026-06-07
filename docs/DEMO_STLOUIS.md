# St. Louis Demo — Copy-Paste Command Sheet
#
# The kernel is ALREADY RUNNING on port 8082.
# Postgres on 55432, RabbitMQ on 55672.
#
# Just copy-paste these commands in order.

########################################################################
# STEP 1: Show it's alive
########################################################################

curl -s http://localhost:8082/health

# Say: "The kernel is running. Let me show you what it does."

########################################################################
# STEP 2: List registered agents
########################################################################

curl -s -H 'Authorization: Bearer *** \
  http://localhost:8082/api/agents | python3 -m json.tool

# Say: "Three agents registered: zoe (orchestrator), osa (Signal Theory
#       brain), and bootstrap-agent. Each has roles and capabilities."

########################################################################
# STEP 3: Issue intent-scoped JWTs
########################################################################

# Token 1: zoe reads a grid sensor
curl -s -X POST http://localhost:8082/api/token \
  -H 'Authorization: Bearer *** \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"zoe","intent_hash":"sensor-read-001","action_type":"read_grid_sensor"}' \
  | python3 -m json.tool

# Say: "Zoe declared she wants to read a grid sensor. The kernel
#       hashed that intent with BLAKE2b, put it in a JWT with a
#       60-second expiration. This token is USELESS for anything else."

# Token 2: zoe adjusts a valve
curl -s -X POST http://localhost:8082/api/token \
  -H 'Authorization: Bearer *** \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"zoe","intent_hash":"valve-control-002","action_type":"adjust_valve"}' \
  | python3 -m json.tool

# Token 3: osa rebalances load
curl -s -X POST http://localhost:8082/api/token \
  -H 'Authorization: Bearer *** \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"osa","intent_hash":"load-balance-003","action_type":"rebalance_load"}' \
  | python3 -m json.tool

# Token 4: zoe generates a report
curl -s -X POST http://localhost:8082/api/token \
  -H 'Authorization: Bearer *** \
  -H 'Content-Type: application/json' \
  -d '{"agent_id":"zoe","intent_hash":"report-gen-004","action_type":"generate_report"}' \
  | python3 -m json.tool

# Say: "Four actions, four audit entries. Each chained to the previous."

########################################################################
# STEP 4: Verify the audit chain (THE MONEY SHOT for Shil)
########################################################################

curl -s http://localhost:8082/api/audit/verify | python3 -m json.tool

# Expected:
#   "entry_count": 4
#   "chain_status": "ok"
#   "sig_status": "ok"

# Say: "The chain is intact. Every entry cryptographically links to
#       the one before it. This is ALCOA+ compliance — the same
#       standard used in FDA-regulated pharmaceutical manufacturing."

########################################################################
# STEP 5: Show the public key
########################################################################

curl -s http://localhost:8082/api/audit/pubkey | python3 -m json.tool

# Say: "Anyone with this public key can independently verify every
#       signature. No trust in the kernel required — just math."

########################################################################
# STEP 6: TAMPER DETECTION (live — for Shil and Goswami)
########################################################################

# Say: "Now let me show you what happens when someone tampers with the log."

# Corrupt entry #2 directly in Postgres
cd ~/vaos-kernel && docker compose --profile db-async exec -T postgres \
  psql -U vaos -d vaos_kernel -c \
  "UPDATE audit_ledger SET status = 'TAMPERED' WHERE sequence = 2;"

# Say: "I just modified entry #2 in the database. Simulating an insider
#       or attacker changing the audit log."

# Restart the kernel so it reloads from the tampered DB
docker compose --profile db-async restart kernel-db-async

# Wait 5 seconds
sleep 5

# Try to reach it
curl -s --connect-timeout 2 http://localhost:8082/health || echo "REFUSED"

# Say: "The kernel REFUSES TO START. It won't serve a single request."

# Show the logs — this is the proof
docker compose --profile db-async logs --tail=3 kernel-db-async

# The last line will say:
#   "create async DB ledger: verify persisted audit chain: entry ... is invalid"

# Say: "The kernel detected the tampering on startup and shut down.
#       This is not a warning — it's a HARD GATE. The system will not
#       operate with a compromised audit trail.
#
#       For NERC CIP: no one can alter your logs without the system
#       itself refusing to function. That's cryptographic enforcement,
#       not just policy."

########################################################################
# STEP 7: Recover (clean up for next demo or questions)
########################################################################

# Fix the DB
docker compose --profile db-async exec -T postgres \
  psql -U vaos -d vaos_kernel -c "DELETE FROM audit_ledger;"

# Restart on clean DB
docker compose --profile db-async restart kernel-db-async

sleep 5
curl -s http://localhost:8082/health

# Say: "After clearing the tampered data, the kernel starts normally."

########################################################################
# STEP 8: Show the IETF draft (for Goswami)
########################################################################

cat ~/vaos-kernel/docs/specs/draft-goswami-agentic-jwt-00.txt | head -30

# Say: "Abhishek, this is your draft. Section 1 describes the
#       intent-execution separation problem. What you just saw is
#       the first independent implementation that closes that gap.
#       The GitHub commit history timestamps everything."

########################################################################
# STEP 9: Show benchmark numbers
########################################################################

# Open in browser:
open https://github.com/jmanhype/vaos-kernel#benchmark-results

# Say: "50,774 requests per second with full ALCOA+ attestation.
#       The security layer adds 0.5% overhead."

########################################################################
# CLEANUP (after the meeting)
########################################################################

cd ~/vaos-kernel
VAOS_POSTGRES_PORT=55432 VAOS_AMQP_PORT=55672 \
  docker compose --profile db-async down -v

########################################################################
# ALCOA+ MAPPING (have this visible during the demo)
########################################################################
#
#   Attributable    →  Agent ID in every audit entry
#   Legible         →  JSON + human-readable action names
#   Contemporaneous →  Timestamp set at Record() time
#   Original        →  Hash chain from genesis
#   Accurate        →  Intent fingerprint matches action
#   Complete        →  No gaps (chain verifies all entries)
#   Consistent      →  Same schema across all modes
#   Enduring        →  Postgres + nanosecond replay after restart
#   Available       →  HTTP/gRPC query + WebSocket push
#
