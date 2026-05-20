---
name: domotz-fahm
description: Use when querying FAHM/BitGiants Domotz collectors and devices for status, inventory, topology, uptime, history, configuration backup status, and safe remediation discovery/execution through the claw-domotz wrapper. Enforces read-first and approval-before-write guardrails.
version: 1.0.0
author: Capacitor / Hermes Agent
license: MIT
metadata:
  hermes:
    tags: [domotz, fahm, bitgiants, monitoring, remediation, clawnet, wrapper]
    related_skills: [openclaw-operations, api-credentials, native-mcp]
---

# Domotz FAHM / BitGiants Operations

## Overview

Use `claw-domotz` for Domotz Public API work. It is a ClawNet-style wrapper in `/home/admin/clawnet-wrappers/domotz/` and symlinked as `/home/admin/bin/claw-domotz`.

The wrapper prefers a future Vault API proxy route named `domotz`; until that exists, it can use `DOMOTZ_API_KEY` or `~/.config/domotz/config.json` with `{ "api_key": "..." }`. Do not commit or print API keys.

Domotz MCP (`https://mcp.domotz.com/mcp`) is OAuth/JWT-backed and does not accept the Public API key. Many MCP-advertised read/status capabilities are available via the REST API and exposed through this wrapper.

## When to Use

Use this skill when Serg or Bob needs to:

- List Domotz collectors/agents and their online/offline status.
- Query FAHM/client device inventory, online/down counts, device details, IPs, and SNMP status.
- Check collector/device uptime.
- Pull network topology edges.
- Inspect network event history, RTD history, inventory fields, variables, or config backup history.
- Discover available power/remediation actions for a device.
- Execute an approved power/remediation action with exact target IDs.

Do **not** use this for generic network checks outside Domotz or for unauthenticated MCP OAuth setup.

## Authentication

Check the API proxy first:

```bash
curl -s http://127.0.0.1:8091/health | python3 -m json.tool
```

If a `domotz` route exists, the wrapper will use it. Otherwise configure local auth outside Git:

```bash
export DOMOTZ_API_KEY="..."
# or
mkdir -p ~/.config/domotz
printf '{"api_key":"..."}\n' > ~/.config/domotz/config.json
chmod 600 ~/.config/domotz/config.json
```

REST API base:

```text
https://api-us-east-1-cell-1.domotz.com/public-api/v1
```

OpenAPI:

```bash
claw-domotz openapi > /tmp/domotz-openapi.json
```

## Read-Only Commands

```bash
# Verify auth and collector visibility
claw-domotz health

# Collectors / agents
claw-domotz agents --compact
claw-domotz agents --summary
claw-domotz agent "Brunswick" --full

# Device inventory
claw-domotz devices "Brunswick" --summary
claw-domotz devices "Brunswick" --status ONLINE --compact --limit 20
claw-domotz devices "Brunswick" --status DOWN --compact --limit 20
claw-domotz devices "Brunswick" --search printer --compact

# Device detail by name/IP/MAC/id, with fuzzy matching
claw-domotz device "Brunswick" "192.168.1.38" --full

# Uptime
claw-domotz uptime "Brunswick"
claw-domotz uptime "Brunswick" "192.168.1.38"

# Topology and history
claw-domotz topology "Brunswick"
claw-domotz events "Brunswick"
claw-domotz events "Brunswick" "192.168.1.38"
claw-domotz rtd "Brunswick" "192.168.1.38"

# Device-specific operational data
claw-domotz inventory "Brunswick" "192.168.1.38"
claw-domotz variables "Brunswick" "192.168.1.38"
claw-domotz config-history "Brunswick" "192.168.1.38"

# Remediation capability discovery only
claw-domotz power-actions "Brunswick" "192.168.1.38"
claw-domotz outlets "Brunswick" "PDU-or-switch-device"
```

## Write / Remediation Commands

Write commands are disabled unless `--confirm-write` is present. Only run after Serg explicitly approves the exact collector, device, and action.

```bash
# Device power actions; action is on/off/cycle/software_reboot
claw-domotz power "Brunswick" "DEVICE_ID" software_reboot --confirm-write
claw-domotz power "Brunswick" "DEVICE_ID" cycle --confirm-write

# Outlet action; action is on/off/cycle
claw-domotz outlet-action "Brunswick" "PDU_DEVICE_ID" OUTLET_ID cycle --confirm-write
```

Before asking for approval, collect:

- collector name and ID
- device name, ID, IP/MAC, current status
- available action flags from `power-actions` or outlet list
- likely blast radius / upstream dependency from topology where relevant

Example approval wording:

```text
I found device AP-LOBBY-3 (device_id 123, 10.x.x.x) DOWN on collector FAHM (agent_id 456). Domotz reports software_reboot is available. This will attempt to reboot that device. Reply approve reboot AP-LOBBY-3 to proceed.
```

## Output Modes

- Default: JSON
- `--compact`: human-readable rows for list commands
- `--full`: raw JSON, useful for debugging
- `--summary`: counts/status summaries for agents/devices

## Current Verified Functionality

Live tests with the Domotz Public API key confirmed:

- `health` reaches the API and lists collectors.
- `agents` returned 2 collectors.
- `devices` returned inventory; one collector returned 888 devices.
- Device status counts, details, uptime, topology, network events, RTD history, variables, config-history, power-actions, and outlets endpoints respond.
- `power-actions` can show action flags such as `on`, `off`, `cycle`, and `software_reboot`.
- Config backup history may return HTTP 412 for devices without a config management driver; treat this as a device capability limitation, not auth failure.

## Common Pitfalls

1. **Trying the Public API key against MCP.** MCP rejects it (`X-Api-Key` = missing Authorization; Bearer public API key = malformed JWT). Use REST wrapper unless implementing OAuth.
2. **Assuming a down collector means no device data.** Domotz may still return last-known device inventory.
3. **Executing remediation from fuzzy names.** Use exact IDs for approved writes when possible.
4. **Skipping read-back verification.** After any write, re-run `device`, `uptime`, and relevant `events`/alerts.
5. **Committing secrets.** The wrapper and skill must never contain raw API keys.

## Verification Checklist

- [ ] `claw-domotz health` succeeds.
- [ ] Correct collector resolved; ambiguity handled.
- [ ] Read-only status/device/topology data gathered before action.
- [ ] Exact device ID/action included in approval request.
- [ ] `--confirm-write` only used after approval.
- [ ] Post-action status re-read and reported.
