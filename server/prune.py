#!/usr/bin/env python3
"""Prune stale lobbies from server/lobby.json and commit changes.

Run by .github/workflows/prune.yml (every 30 minutes). Relies on
actions/checkout having the repo checked out at the repo root.
"""
import json
import os
import subprocess
import time

STALE_AFTER_SEC = 30 * 60
PATH = "server/lobby.json"
REMOTE = "https://github.com/the-lust/stardew-valley-online-launcher.git"


def main():
    token = os.environ.get("GITHUB_TOKEN", "")
    if not os.path.exists(PATH):
        print("no lobby store found, nothing to do")
        return
    with open(PATH, "r", encoding="utf-8") as f:
        store = json.load(f)
    now = int(time.time())
    before = len(store.get("lobbies", []))
    store["lobbies"] = [
        l for l in store.get("lobbies", [])
        if now - l.get("last_seen", 0) < STALE_AFTER_SEC
    ]
    after = len(store["lobbies"])
    if before == after:
        print("nothing stale, no commit")
        return
    with open(PATH, "w", encoding="utf-8") as f:
        json.dump(store, f, indent=2)
    subprocess.run(["git", "config", "user.name", "lobby-bot"], check=True)
    subprocess.run(["git", "config", "user.email", "lobby-bot@users.noreply.github.com"], check=True)
    subprocess.run(["git", "add", PATH], check=True)
    subprocess.run(["git", "commit", "-m", f"prune {before - after} stale lobby(s)"], check=True)
    push = f"https://x-access-token:{token}@{REMOTE.split('//')[1]}" if token else REMOTE
    subprocess.run(["git", "push", push, "HEAD:main"], check=True)
    print(f"pruned {before - after} stale lobby(s)")


if __name__ == "__main__":
    main()
