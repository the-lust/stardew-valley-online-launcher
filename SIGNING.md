# Signing game.exe via SignPath.io (free OSS code signing)

The goal: every build of `game.exe` carries a **real Authenticode
signature**, which is what gets AV engines (Microsoft, CrowdStrike, ...) to
stop flagging a freshly compiled unsigned homebrew binary.

The Genshin Impact FPS unlocker uses exactly this service — see its README:
> "Free code signing provided by SignPath.io" — https://signpath.io/

The signature is applied by **SignPath's** certificate (identity will read
"SignPath.io"), not by us and not by any third-party project — nothing about
"genshin" appears anywhere in our build.

## How it works

SignPath offers free signing for **open-source projects**:

1. The source must live in a **public** GitHub repository.
2. Apply on https://signpath.io/OSS/ (or the "Open Source" section on their
   site) with the repo URL.
3. After approval, you get an `organization-id`, a `project-slug` and a
   `signing-policy-slug`.
4. Their GitHub Action (`signpath/signpath-actions`) signs the artifact
   produced by our build pipeline. The build happens on GitHub Actions;
   SignPath's service applies the signature (the private key never leaves
   their infrastructure).
5. The signed `game.exe` is attached to the workflow run / release.

## Files needed for this repo

- `.github/workflows/build.yml` — builds `main.cpp` on a
  `windows-latest` runner (MSVC toolset), then runs the SignPath action.
- Secrets (repo Settings → Secrets and variables → Actions):
  - `SIGNPATH_ORG_ID`
  - `SIGNPATH_PROJECT_SLUG`
  - `SIGNPATH_SIGNING_POLICY_SLUG`
  - `SIGNPATH_API_TOKEN` (issued by SignPath)

Once the workflow template is confirmed by SignPath's documentation, fill in
the exact action inputs and commit the workflow.

## Verification

```
powershell -ExecutionPolicy Bypass -File .\vtcheck.ps1
```

runs the built `game.exe` through VirusTotal (needs `.vtkey` — a VirusTotal
API key — next to the script, which is gitignored).

## Also

- Even with a signature, submit each release hash to Microsoft's
  false-positive portal once: https://www.microsoft.com/en-us/wdsi/filesubmission
  (File → "False positive (benign)" → attach `game.exe`).
- Goal state: VirusTotal `0/71`.
