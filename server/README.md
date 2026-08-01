# Lobby registry server

The online co-op lobby registry used by `game.exe`. Everything lives in this
repo; no external database is needed.

```
api/lobby.py          Vercel Python serverless function (the "server")
server/lobby.json     persistent lobby store (GitHub = the "database")
server/config.json    runtime config read by the launcher (Vercel URL)
server/prune.py       stale-lobby pruner (called by the cron workflow)
.github/workflows/prune.yml   cron: prunes stale lobbies every 30 min
```

## How it works

1. `game.exe` fetches `server/config.json` (raw.githubusercontent) for the API URL.
2. On **Launch** the launcher:
   - asks `/api/ip` for its own public IP,
   - registers a lobby via `POST /api/lobby` `{name, port}`,
   - fetches all active lobbies via `GET /api/lobby`,
   - writes every lobby IP into `steam_settings/custom_broadcasts.txt` so
     gbe_fork broadcasts to them over the internet,
   - starts `StardewModdingAPI.exe`.
3. When the game exits, the launcher unregisters via `DELETE /api/lobby`.
4. Stale lobbies (no refresh in 30 min) are dropped on every request and by
   the cron workflow.

Internet play requires the **host** to forward UDP+TCP port **47584**
(the gbe_fork listen port) on their router.

## Deploy to Vercel

1. Push this repository to GitHub.
2. Create a GitHub **Personal Access Token (classic)** with `repo` scope.
3. In Vercel: New Project -> import `the-lust/stardew-valley-online-launcher`.
   - Framework Preset: **Other**
   - Build Command / Output: empty (pure serverless)
4. Vercel project settings -> Environment Variables:
   - `GITHUB_TOKEN` = the PAT from step 2
5. Deploy. The function is auto-detected at `/api/lobby`.
6. Verify with curl:
   ```sh
   curl https://<your-app>.vercel.app/api/ip
   curl -X POST https://<your-app>.vercel.app/api/lobby -H "Content-Type: application/json" -d "{\"name\":\"tester\"}"
   curl https://<your-app>.vercel.app/api/lobby
   curl -X DELETE https://<your-app>.vercel.app/api/lobby -H "Content-Type: application/json" -d "{\"name\":\"tester\"}"
   ```
7. Put the deployed URL into `server/config.json` (`"api"` field), commit and
   push. `game.exe` picks it up automatically at launch (no recompile needed).

## GitHub workflow

`lobby-prune` runs every 30 minutes (or on manual dispatch). It prunes stale
entries from `server/lobby.json` and commits the change. It needs the repo
`GITHUB_TOKEN` secret with `contents: write` permission (the built-in
`GITHUB_TOKEN` has this inside the workflow).

## API reference

| Method | Path        | Body / Query           | Returns |
|--------|-------------|------------------------|---------|
| GET    | `/api/ip`   | -                      | plain text public IP |
| GET    | `/api/lobby`| -                      | JSON lobby list + `now` timestamp |
| POST   | `/api/lobby`| `{"name","port"}`     | the created/refreshed lobby |
| DELETE | `/api/lobby`| `{"name"}`            | `{"removed": name}` |

`name` max 24 chars. Entries with `last_seen` older than 30 minutes are
considered stale and dropped.
