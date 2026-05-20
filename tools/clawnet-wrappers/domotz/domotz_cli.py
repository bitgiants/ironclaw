#!/usr/bin/env python3
"""claw-domotz: ClawNet-style CLI for Domotz Public API.

Read-only network monitoring by default. Remediation/write operations require
--confirm-write plus exact target IDs/actions. The CLI prefers a future Vault
API proxy route (/domotz), but currently supports DOMOTZ_API_KEY or a local
0600 config file for the Domotz Public API.

Auth precedence:
  1. DOMOTZ_PROXY_URL + configured proxy route (default route name: domotz)
  2. DOMOTZ_API_KEY environment variable
  3. ~/.config/domotz/config.json with {"api_key": "..."}

No external dependencies; stdlib only.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

API_BASE_DEFAULT = "https://api-us-east-1-cell-1.domotz.com/public-api/v1"
API_BASE = os.environ.get("DOMOTZ_API_BASE", API_BASE_DEFAULT).rstrip("/")
PROXY_BASE = os.environ.get("DOMOTZ_PROXY_URL", "https://127.0.0.1:8090").rstrip("/")
PROXY_ROUTE = os.environ.get("DOMOTZ_PROXY_ROUTE", "domotz").strip("/")
HEALTH_URL = os.environ.get("DOMOTZ_HEALTH_URL", "http://127.0.0.1:8091/health")
TIMEOUT_DEFAULT = int(os.environ.get("DOMOTZ_TIMEOUT", "30"))
RATE_LIMIT_SLEEP = float(os.environ.get("DOMOTZ_RATE_SLEEP", "0.15"))
CONFIG_PATH = Path(os.environ.get("DOMOTZ_CONFIG", "~/.config/domotz/config.json")).expanduser()
CACHE_DIR = Path(os.environ.get("DOMOTZ_CACHE_DIR", "~/.cache/claw-domotz")).expanduser()
CACHE_TTL = int(os.environ.get("DOMOTZ_CACHE_TTL", "180"))

_ssl_unverified = ssl.create_default_context()
_ssl_unverified.check_hostname = False
_ssl_unverified.verify_mode = ssl.CERT_NONE


class APIError(Exception):
    def __init__(self, message: str, status: int = 0, body: str = "") -> None:
        super().__init__(message)
        self.status = status
        self.body = body


def redact(text: str) -> str:
    text = re.sub(r"(X-Api-Key: )[^\s]+", r"\1<redacted>", text)
    text = re.sub(r"([?&]api[_-]?key=)[^&\s]+", r"\1<redacted>", text, flags=re.I)
    text = re.sub(r"([A-Za-z0-9_\-]{24,})", lambda m: "<redacted>" if len(m.group(1)) > 32 else m.group(1), text)
    return text


def load_api_key() -> Optional[str]:
    key = os.environ.get("DOMOTZ_API_KEY", "").strip()
    if key:
        return key
    if CONFIG_PATH.exists():
        try:
            data = json.loads(CONFIG_PATH.read_text())
            key = str(data.get("api_key", "")).strip()
            if key:
                return key
        except Exception as exc:
            raise APIError(f"Failed reading {CONFIG_PATH}: {exc}") from exc
    return None


def has_proxy_route() -> bool:
    try:
        req = urllib.request.Request(HEALTH_URL, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
        return any((r.get("name") == PROXY_ROUTE or r.get("prefix") == f"/{PROXY_ROUTE}") for r in data.get("routes", []))
    except Exception:
        return False


def request_json(method: str, url: str, *, headers: Optional[Dict[str, str]] = None, body: Any = None, timeout: int = TIMEOUT_DEFAULT, insecure: bool = False) -> Any:
    hdrs = {"Accept": "application/json", "User-Agent": "claw-domotz/0.1"}
    if headers:
        hdrs.update(headers)
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        ctx = _ssl_unverified if insecure else None
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read().decode("utf-8", "replace")
            if not raw.strip():
                return {}
            return json.loads(raw)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", "replace") if exc.fp else ""
        raise APIError(f"HTTP {exc.code}: {redact(raw[:700])}", exc.code, raw) from exc
    except urllib.error.URLError as exc:
        raise APIError(f"Connection error: {exc.reason}") from exc
    except json.JSONDecodeError as exc:
        raise APIError(f"Invalid JSON from {url}: {exc}") from exc
    finally:
        time.sleep(RATE_LIMIT_SLEEP)


def api_call(method: str, path: str, *, params: Optional[Dict[str, Any]] = None, body: Any = None, timeout: int = TIMEOUT_DEFAULT) -> Any:
    path = "/" + path.lstrip("/")
    clean_params = {k: v for k, v in (params or {}).items() if v is not None}
    query = "?" + urllib.parse.urlencode(clean_params, doseq=True) if clean_params else ""
    if has_proxy_route():
        # Future path: proxy injects X-Api-Key and forwards to Domotz.
        url = f"{PROXY_BASE}/{PROXY_ROUTE}{path}{query}"
        return request_json(method, url, body=body, timeout=timeout, insecure=True)
    key = load_api_key()
    if not key:
        raise APIError(
            "No Domotz auth configured. Set DOMOTZ_API_KEY, create ~/.config/domotz/config.json "
            "with api_key, or add a Vault proxy route named domotz."
        )
    url = f"{API_BASE}{path}{query}"
    return request_json(method, url, headers={"X-Api-Key": key}, body=body, timeout=timeout)


def cache_get(name: str) -> Optional[Any]:
    try:
        p = CACHE_DIR / f"{name}.json"
        if not p.exists() or time.time() - p.stat().st_mtime > CACHE_TTL:
            return None
        return json.loads(p.read_text())
    except Exception:
        return None


def cache_set(name: str, value: Any) -> None:
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        (CACHE_DIR / f"{name}.json").write_text(json.dumps(value))
    except Exception:
        pass


def list_agents(force: bool = False) -> List[Dict[str, Any]]:
    if not force:
        c = cache_get("agents")
        if isinstance(c, list):
            return c
    data = api_call("GET", "/agent")
    if not isinstance(data, list):
        raise APIError("Unexpected /agent response shape")
    cache_set("agents", data)
    return data


def agent_name(agent: Dict[str, Any]) -> str:
    return str(agent.get("display_name") or agent.get("name") or agent.get("id") or "")


def device_name(dev: Dict[str, Any]) -> str:
    return str(dev.get("display_name") or dev.get("name") or dev.get("id") or "")


def normalize(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", s.lower())


def resolve_agent(value: str) -> Dict[str, Any]:
    agents = list_agents()
    if value.isdigit():
        for a in agents:
            if str(a.get("id")) == value:
                return a
    nv = normalize(value)
    exact = [a for a in agents if normalize(agent_name(a)) == nv]
    contains = [a for a in agents if nv and nv in normalize(agent_name(a))]
    matches = exact or contains
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise APIError("Ambiguous collector. Matches: " + ", ".join(f"{agent_name(a)} ({a.get('id')})" for a in matches[:10]))
    raise APIError("No collector matched. Available: " + ", ".join(f"{agent_name(a)} ({a.get('id')})" for a in agents[:20]))


def list_devices(agent_id: str, force: bool = False) -> List[Dict[str, Any]]:
    cname = f"devices_{agent_id}"
    if not force:
        c = cache_get(cname)
        if isinstance(c, list):
            return c
    data = api_call("GET", f"/agent/{agent_id}/device")
    if not isinstance(data, list):
        raise APIError("Unexpected devices response shape")
    cache_set(cname, data)
    return data


def resolve_device(agent_id: str, value: str) -> Dict[str, Any]:
    devices = list_devices(agent_id)
    if value.isdigit():
        for d in devices:
            if str(d.get("id")) == value:
                return d
    nv = normalize(value)
    def fields(d: Dict[str, Any]) -> List[str]:
        vals = [device_name(d), str(d.get("id") or ""), str(d.get("mac_address") or "")]
        vals += [str(x) for x in d.get("ip_addresses") or []]
        return vals
    exact = [d for d in devices if any(normalize(v) == nv for v in fields(d))]
    contains = [d for d in devices if nv and any(nv in normalize(v) for v in fields(d))]
    matches = exact or contains
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise APIError("Ambiguous device. Matches: " + ", ".join(f"{device_name(d)} ({d.get('id')}, {','.join(d.get('ip_addresses') or [])})" for d in matches[:10]))
    raise APIError(f"No device matched '{value}'")


def status_value(obj: Dict[str, Any]) -> str:
    s = obj.get("status")
    if isinstance(s, dict):
        return str(s.get("value") or "")
    return str(s or "")


def type_label(dev: Dict[str, Any]) -> str:
    t = dev.get("type")
    return str(t.get("label") if isinstance(t, dict) else (t or ""))


def ip_list(dev: Dict[str, Any]) -> str:
    return ",".join(str(x) for x in (dev.get("ip_addresses") or []))


def output(data: Any, args: argparse.Namespace, compact_fn=None) -> None:
    if getattr(args, "compact", False) and compact_fn:
        compact_fn(data)
    elif getattr(args, "full", False):
        print(json.dumps(data, indent=2, sort_keys=True))
    else:
        print(json.dumps(data, indent=2, sort_keys=True))


def print_agents(agents: List[Dict[str, Any]]) -> None:
    for a in agents:
        st = status_value(a)
        last = (a.get("status") or {}).get("last_change") if isinstance(a.get("status"), dict) else ""
        print(f"{a.get('id')}\t{st}\t{agent_name(a)}\tlast_change={last}")


def print_devices(devices: List[Dict[str, Any]]) -> None:
    for d in devices:
        print(f"{d.get('id')}\t{status_value(d)}\t{device_name(d)}\t{ip_list(d)}\t{type_label(d)}\tsnmp={d.get('snmp_status','')}")


def summarize_agents(agents: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts: Dict[str, int] = {}
    for a in agents:
        counts[status_value(a)] = counts.get(status_value(a), 0) + 1
    return {"count": len(agents), "status_counts": counts, "agents": agents}


def summarize_devices(devices: List[Dict[str, Any]]) -> Dict[str, Any]:
    counts: Dict[str, int] = {}
    type_counts: Dict[str, int] = {}
    for d in devices:
        counts[status_value(d)] = counts.get(status_value(d), 0) + 1
        lbl = type_label(d) or "Unknown"
        type_counts[lbl] = type_counts.get(lbl, 0) + 1
    return {"count": len(devices), "status_counts": counts, "type_counts": dict(sorted(type_counts.items(), key=lambda x: x[1], reverse=True)[:20]), "devices": devices}


def cmd_health(args: argparse.Namespace) -> None:
    result: Dict[str, Any] = {"api_base": API_BASE, "proxy_route": PROXY_ROUTE, "proxy_has_route": has_proxy_route(), "auth_source": None}
    if result["proxy_has_route"]:
        result["auth_source"] = "vault-proxy"
    elif os.environ.get("DOMOTZ_API_KEY"):
        result["auth_source"] = "DOMOTZ_API_KEY"
    elif CONFIG_PATH.exists():
        result["auth_source"] = str(CONFIG_PATH)
    else:
        result["auth_source"] = "none"
    try:
        agents = list_agents(force=True)
        result.update({"ok": True, "agent_count": len(agents), "agents": [{"id": a.get("id"), "display_name": agent_name(a), "status": status_value(a)} for a in agents]})
    except Exception as exc:
        result.update({"ok": False, "error": redact(str(exc))})
    output(result, args)


def cmd_agents(args: argparse.Namespace) -> None:
    agents = list_agents(force=args.no_cache)
    data = summarize_agents(agents) if args.summary else agents
    output(data, args, print_agents if not args.summary else None)


def cmd_agent(args: argparse.Namespace) -> None:
    a = resolve_agent(args.agent)
    data = api_call("GET", f"/agent/{a['id']}")
    output(data, args)


def filtered_devices(devices: List[Dict[str, Any]], args: argparse.Namespace) -> List[Dict[str, Any]]:
    out = devices
    if args.status:
        want = args.status.upper()
        out = [d for d in out if status_value(d).upper() == want]
    if args.search:
        q = normalize(args.search)
        out = [d for d in out if q in normalize(" ".join([device_name(d), ip_list(d), str(d.get("mac_address") or ""), type_label(d)]))]
    if args.limit:
        out = out[: args.limit]
    return out


def cmd_devices(args: argparse.Namespace) -> None:
    a = resolve_agent(args.agent)
    devs = filtered_devices(list_devices(str(a["id"]), force=args.no_cache), args)
    data = summarize_devices(devs) if args.summary else devs
    output(data, args, print_devices if not args.summary else None)


def cmd_device(args: argparse.Namespace) -> None:
    a = resolve_agent(args.agent)
    d = resolve_device(str(a["id"]), args.device)
    data = api_call("GET", f"/agent/{a['id']}/device/{d['id']}")
    output(data, args)


def cmd_uptime(args: argparse.Namespace) -> None:
    a = resolve_agent(args.agent)
    if args.device:
        d = resolve_device(str(a["id"]), args.device)
        data = api_call("GET", f"/agent/{a['id']}/device/{d['id']}/uptime")
    else:
        data = api_call("GET", f"/agent/{a['id']}/uptime")
    output(data, args)


def cmd_topology(args: argparse.Namespace) -> None:
    a = resolve_agent(args.agent)
    data = api_call("GET", f"/agent/{a['id']}/network-topology")
    output(data, args)


def cmd_events(args: argparse.Namespace) -> None:
    a = resolve_agent(args.agent)
    if args.device:
        d = resolve_device(str(a["id"]), args.device)
        path = f"/agent/{a['id']}/device/{d['id']}/history/network/event"
    else:
        path = f"/agent/{a['id']}/history/network/event"
    data = api_call("GET", path)
    output(data, args)


def cmd_inventory(args: argparse.Namespace) -> None:
    a = resolve_agent(args.agent)
    d = resolve_device(str(a["id"]), args.device)
    data = api_call("GET", f"/agent/{a['id']}/device/{d['id']}/inventory")
    output(data, args)


def cmd_variables(args: argparse.Namespace) -> None:
    a = resolve_agent(args.agent)
    d = resolve_device(str(a["id"]), args.device)
    data = api_call("GET", f"/agent/{a['id']}/device/{d['id']}/variable")
    output(data, args)


def cmd_rtd(args: argparse.Namespace) -> None:
    a = resolve_agent(args.agent)
    d = resolve_device(str(a["id"]), args.device)
    data = api_call("GET", f"/agent/{a['id']}/device/{d['id']}/history/rtd")
    output(data, args)


def cmd_config_history(args: argparse.Namespace) -> None:
    a = resolve_agent(args.agent)
    d = resolve_device(str(a["id"]), args.device)
    data = api_call("GET", f"/agent/{a['id']}/device/{d['id']}/configuration-management/history")
    output(data, args)


def cmd_power_actions(args: argparse.Namespace) -> None:
    a = resolve_agent(args.agent)
    d = resolve_device(str(a["id"]), args.device)
    data = api_call("GET", f"/agent/{a['id']}/device/{d['id']}/action/power")
    output(data, args)


def cmd_outlets(args: argparse.Namespace) -> None:
    a = resolve_agent(args.agent)
    d = resolve_device(str(a["id"]), args.device)
    data = api_call("GET", f"/agent/{a['id']}/device/{d['id']}/power-outlet")
    output(data, args)


def require_confirm(args: argparse.Namespace, message: str) -> None:
    if not args.confirm_write:
        raise APIError(message + " Refusing: pass --confirm-write after explicit Serg approval.")


def cmd_power(args: argparse.Namespace) -> None:
    a = resolve_agent(args.agent)
    d = resolve_device(str(a["id"]), args.device)
    actions = api_call("GET", f"/agent/{a['id']}/device/{d['id']}/action/power")
    if isinstance(actions, dict) and args.action in actions and not actions.get(args.action):
        raise APIError(f"Domotz reports action '{args.action}' is not available for {device_name(d)} ({d['id']})")
    require_confirm(args, f"Power action '{args.action}' on {device_name(d)} ({d['id']}) via collector {agent_name(a)} ({a['id']}).")
    data = api_call("POST", f"/agent/{a['id']}/device/{d['id']}/action/power/{args.action}")
    output({"requested": True, "agent_id": a["id"], "device_id": d["id"], "action": args.action, "result": data}, args)


def cmd_outlet_action(args: argparse.Namespace) -> None:
    a = resolve_agent(args.agent)
    d = resolve_device(str(a["id"]), args.device)
    require_confirm(args, f"Outlet action '{args.action}' on outlet {args.outlet_id} for {device_name(d)} ({d['id']}).")
    data = api_call("POST", f"/agent/{a['id']}/device/{d['id']}/power-outlet/{args.outlet_id}/action/{args.action}")
    output({"requested": True, "agent_id": a["id"], "device_id": d["id"], "outlet_id": args.outlet_id, "action": args.action, "result": data}, args)


def cmd_openapi(args: argparse.Namespace) -> None:
    data = request_json("GET", f"{API_BASE}/meta/open-api-definition", timeout=args.timeout)
    output(data, args)


def add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--compact", "-c", action="store_true", help="compact text output where supported")
    p.add_argument("--full", "-f", action="store_true", help="raw/full JSON output")
    p.add_argument("--timeout", type=int, default=TIMEOUT_DEFAULT)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="claw-domotz", description="Domotz Public API CLI for ClawNet/Bob")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("health", help="verify auth and list collector count"); add_common(p); p.set_defaults(func=cmd_health)
    p = sub.add_parser("agents", help="list collectors/agents"); add_common(p); p.add_argument("--summary", action="store_true"); p.add_argument("--no-cache", action="store_true"); p.set_defaults(func=cmd_agents)
    p = sub.add_parser("agent", help="collector details"); add_common(p); p.add_argument("agent"); p.set_defaults(func=cmd_agent)
    p = sub.add_parser("devices", help="list devices for a collector"); add_common(p); p.add_argument("agent"); p.add_argument("--status", help="ONLINE/DOWN/etc"); p.add_argument("--search", help="filter by name/IP/MAC/type"); p.add_argument("--limit", type=int); p.add_argument("--summary", action="store_true"); p.add_argument("--no-cache", action="store_true"); p.set_defaults(func=cmd_devices)
    p = sub.add_parser("device", help="device details"); add_common(p); p.add_argument("agent"); p.add_argument("device"); p.set_defaults(func=cmd_device)
    p = sub.add_parser("uptime", help="collector or device uptime"); add_common(p); p.add_argument("agent"); p.add_argument("device", nargs="?"); p.set_defaults(func=cmd_uptime)
    p = sub.add_parser("topology", help="network topology edges"); add_common(p); p.add_argument("agent"); p.set_defaults(func=cmd_topology)
    p = sub.add_parser("events", help="collector or device network events"); add_common(p); p.add_argument("agent"); p.add_argument("device", nargs="?"); p.set_defaults(func=cmd_events)
    p = sub.add_parser("inventory", help="device inventory fields"); add_common(p); p.add_argument("agent"); p.add_argument("device"); p.set_defaults(func=cmd_inventory)
    p = sub.add_parser("variables", help="device variables"); add_common(p); p.add_argument("agent"); p.add_argument("device"); p.set_defaults(func=cmd_variables)
    p = sub.add_parser("rtd", help="device round trip delay history"); add_common(p); p.add_argument("agent"); p.add_argument("device"); p.set_defaults(func=cmd_rtd)
    p = sub.add_parser("config-history", help="device configuration backup history"); add_common(p); p.add_argument("agent"); p.add_argument("device"); p.set_defaults(func=cmd_config_history)
    p = sub.add_parser("power-actions", help="discover available device power actions"); add_common(p); p.add_argument("agent"); p.add_argument("device"); p.set_defaults(func=cmd_power_actions)
    p = sub.add_parser("outlets", help="list device power outlets"); add_common(p); p.add_argument("agent"); p.add_argument("device"); p.set_defaults(func=cmd_outlets)
    p = sub.add_parser("power", help="execute device power action (write; approval required)"); add_common(p); p.add_argument("agent"); p.add_argument("device"); p.add_argument("action", choices=["on", "off", "cycle", "software_reboot"]); p.add_argument("--confirm-write", action="store_true"); p.set_defaults(func=cmd_power)
    p = sub.add_parser("outlet-action", help="execute outlet power action (write; approval required)"); add_common(p); p.add_argument("agent"); p.add_argument("device"); p.add_argument("outlet_id"); p.add_argument("action", choices=["on", "off", "cycle"]); p.add_argument("--confirm-write", action="store_true"); p.set_defaults(func=cmd_outlet_action)
    p = sub.add_parser("openapi", help="fetch public OpenAPI definition"); add_common(p); p.set_defaults(func=cmd_openapi)
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        args.func(args)
        return 0
    except APIError as exc:
        print(f"ERROR: {redact(str(exc))}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
