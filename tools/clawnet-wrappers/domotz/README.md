# claw-domotz

ClawNet-style Domotz Public API wrapper for Bob/BitGiants operations.

## Authentication

Preferred future path: local Vault API proxy route named `domotz`.

Current supported paths:

```bash
export DOMOTZ_API_KEY="..."                  # preferred for ad-hoc tests
# or create ~/.config/domotz/config.json with {"api_key":"..."}, chmod 600
```

Do not commit API keys.

## Examples

```bash
claw-domotz health
claw-domotz agents --compact
claw-domotz devices "Brunswick" --summary
claw-domotz devices "Brunswick" --status ONLINE --compact --limit 20
claw-domotz device "Brunswick" "192.168.1.38"
claw-domotz uptime "Brunswick"
claw-domotz uptime "Brunswick" "192.168.1.38"
claw-domotz topology "Brunswick"
claw-domotz power-actions "Brunswick" "192.168.1.38"
```

Write/remediation commands require exact target and `--confirm-write` after explicit approval:

```bash
claw-domotz power "Brunswick" "DEVICE_ID" software_reboot --confirm-write
claw-domotz outlet-action "Brunswick" "PDU_DEVICE_ID" OUTLET_ID cycle --confirm-write
```
