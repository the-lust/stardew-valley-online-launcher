# game.exe — Stardew Valley private co-op launcher

A single-file launcher for a private, fully-modded Stardew Valley co-op setup.
It provides a small animated terminal menu and one real action right now:
**Launch Game** — starts the game through SMAPI (`StardewModdingAPI.exe`)
with SMAPI's terminal window hidden.

Nothing else is wired yet (`Join Co-op`, `Apply Fix`, `About`, `Exit` are
menu stubs).

## Usage

Place `game.exe` next to the game folder (next to `StardewModdingAPI.exe`
and `Stardew Valley.exe`), double-click it, pick **Launch Game**.

The launcher finds the game folder in this order:

1. `SDV_GAME_DIR` environment variable
2. the folder the launcher itself lives in
3. `..\..\Stardew Valley (413150)\Stardew Valley` relative to the launcher
4. `D:\SDW\Stardew Valley (413150)\Stardew Valley` (default)

Keys: `↑`/`↓` or `W`/`S` navigate, `Enter` selects, `Esc` quits.
`game.exe --selftest` auto-drives the menu for verification.

## Building

Requires Microsoft Visual Studio 2022 Build Tools (MSVC x64 toolset).

```
build.bat
```

Produces `game.exe` (single file, no dependencies beyond Windows itself).

## Files

| File        | Purpose                                          |
|-------------|--------------------------------------------------|
| `main.cpp`  | entire launcher (C++20, Win32, ANSI truecolor)   |
| `game.rc`   | version resource (product metadata)              |
| `game.ico`  | application icon                                 |
| `build.bat` | one-command build (rc + cl + link)               |

## License

MIT — see [LICENSE](LICENSE).
