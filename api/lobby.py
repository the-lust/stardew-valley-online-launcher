"""
Stardew Valley Online - lobby registry (Vercel Python serverless function).

Pairs with:
  * server/prune.py   (GitHub Actions cron that prunes stale entries)
  * game.exe launcher (registers/joins lobbies before launching SMAPI)
  * server/lobby.json (persistent store in this repo)

Endpoints (routed by event["path"]):
  GET    /api/ip        -> text/plain: caller's public IP
  GET    /api/lobby     -> { "lobbies": [ {name, ip, port, last_seen} ... ], "now": ts }
  POST   /api/lobby     -> body {"name": "...", "port": 47584}  register or refresh
  DELETE /api/lobby     -> body {"name": "..."}                 unregister

Persistence goes through the GitHub Contents API (PAT in env GITHUB_TOKEN).
Stale lobbies (no refresh within 30 minutes) are dropped on every access.
"""
import base64
import json
import os
import time
import urllib.error
import urllib.request

OWNER = "the-lust"
REPO = "stardew-valley-online-launcher"
BRANCH = "main"
STORE_PATH = "server/lobby.json"
STALE_AFTER_SEC = 30 * 60
GH_URL = f"https://api.github.com/repos/{OWNER}/{REPO}/contents/{STORE_PATH}"


def _gh(method, url, payload=None):
    req = urllib.request.Request(url, method=method)
    tok = os.environ.get("GITHUB_TOKEN", "")
    if tok:
        req.add_header("Authorization", f"Bearer {tok}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if payload is not None:
        req.add_header("Content-Type", "application/json")
        req.data = json.dumps(payload).encode("utf-8")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read().decode("utf-8")
            return json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"github {method} {e.code}: {e.read().decode(errors='replace')[:300]}")


def _read_store():
    try:
        data = _gh("GET", f"{GH_URL}?ref={BRANCH}")
        content = base64.b64decode(data["content"]).decode("utf-8")
        return json.loads(content), data["sha"]
    except Exception:
        return {"lobbies": []}, None


def _write_store(store, sha):
    for attempt in range(3):
        try:
            payload = {
                "message": "lobby registry update",
                "content": base64.b64encode(
                    json.dumps(store, indent=2).encode("utf-8")).decode("ascii"),
                "branch": BRANCH,
            }
            if sha:
                payload["sha"] = sha
            _gh("PUT", GH_URL, payload)
            return
        except RuntimeError as e:
            if "409" in str(e) and attempt < 2:
                store, sha = _read_store()  # concurrent write: refetch and retry
                continue
            raise


def _prune(store, now):
    store["lobbies"] = [
        l for l in store.get("lobbies", [])
        if now - l.get("last_seen", 0) < STALE_AFTER_SEC
    ]
    return store


def _client_ip(event):
    h = event.get("headers", {}) or {}
    for key in ("x-real-ip", "x-forwarded-for", "cf-connecting-ip"):
        val = h.get(key) or ""
        if val:
            return val.split(",")[0].strip()
    return "0.0.0.0"


def _read_body(event):
    raw = event.get("body") or ""
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode("utf-8", errors="replace")
    try:
        return json.loads(raw) if raw else {}
    except Exception:
        return {}


def _json(status, obj):
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json; charset=utf-8",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
        },
        "body": json.dumps(obj),
    }


def _text(status, text):
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "text/plain; charset=utf-8",
            "Access-Control-Allow-Origin": "*",
        },
        "body": text,
    }


def handler(event, context):
    method = (event.get("httpMethod") or "GET").upper()
    path = (event.get("path") or "/").rstrip("/")
    now = int(time.time())

    if method == "OPTIONS":
        return _json(200, {})

    if path == "/api/ip":
        if method != "GET":
            return _json(405, {"error": "method not allowed"})
        return _text(200, _client_ip(event))

    if path != "/api/lobby":
        return _json(404, {"error": "not found"})

    try:
        store, sha = _read_store()
        store = _prune(store, now)

        if method == "GET":
            return _json(200, {"lobbies": store.get("lobbies", []), "now": now})

        if method == "POST":
            body = _read_body(event)
            name = (body.get("name") or "").strip()
            if not name or len(name) > 24:
                return _json(400, {"error": "invalid name"})
            port = int(body.get("port") or 47584)
            lobby = {"name": name, "ip": _client_ip(event), "port": port, "last_seen": now}
            lst = [l for l in store.get("lobbies", []) if l.get("name") != name]
            lst.append(lobby)
            store["lobbies"] = lst
            _write_store(store, sha)
            return _json(200, lobby)

        if method == "DELETE":
            body = _read_body(event)
            name = (body.get("name") or "").strip()
            store["lobbies"] = [l for l in store.get("lobbies", []) if l.get("name") != name]
            _write_store(store, sha)
            return _json(200, {"removed": name})

        return _json(405, {"error": "method not allowed"})
    except Exception as e:
        return _json(500, {"error": str(e)[:300]})
