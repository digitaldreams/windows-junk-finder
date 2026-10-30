# How JunkFinder for Windows works

The details behind the [README](../README.md): every rule, every safety check, and what is never scanned.

A Windows PowerShell 5.1 script that scans your user profile (`%USERPROFILE%`) and lists disk space you can probably reclaim. It can clean the safe part on request. It sorts findings into **Junk** (rebuilds itself) and **Review** (large, may be the only copy of something), with a rule id and a reason next to each.

## Reading vs cleaning

`junk.cmd` on its own is read-only. It never deletes, moves or modifies anything. It reads file metadata only, never file contents, so cloud files are not downloaded. It does not follow links or junctions. Only `junk.cmd clean` removes anything, and only after you confirm.

The report has four sections in this order: Caches & logs, Dev junk, Old installers, Big files. Rows are sorted by size, largest first. Each row shows size, tier, the path as `~\...`, its age, and `<rule id>: <reason>`. At the end come the totals (`Junk (reclaimable): up to ...`, `Review (check before deleting): up to ...`), a `Skipped` line and a `Notes` footer.

## Clean

```bat
junk.cmd clean <caches|logs|temp|dev|installers|node_modules|vendor>... [--yes] [--permanent]
```

- Sections and the rules they use:

| Section | Rules | What |
|---|---|---|
| `caches` | C1, C1e | browser caches and Electron app caches |
| `logs` | C2 | crash reports older than 7 days |
| `temp` | C3 | temp files older than 7 days |
| `dev` | D3 | package manager download caches |
| `installers` | I1 | old `.msi`, `.msix`, `.msixbundle`, `.appx`, `.appxbundle` in Downloads |
| `node_modules` | D5 | next to `package.json`, with a lock file, unchanged for more than 30 days |
| `vendor` | D6 | next to `composer.json`, with `composer.lock`, unchanged for more than 30 days |

- `big` is refused (`Big files are Review only; delete them by hand`). A missing or unknown section prints the usage line and exits 2.
- Junk tier only. Review findings (D4, D5/D6 without the gates, `.exe`/`.iso` installers, B1, anything with unreadable contents) are never removed, even when their section is named.
- The scan runs first. Then you see `To remove:` (size and path, largest first), `Skipped:` and a total, and you are asked:

```
Move N items (up to X) to the Recycle Bin? Items too large for it are deleted permanently. [y/N]
Permanently delete N items (up to X)? This cannot be undone. [y/N]
```

  The second form is used with `--permanent`. Only `y` or `yes` goes ahead; anything else prints `Aborted; nothing removed.` and exits 0. If nothing matches it prints `Nothing to clean.`
- `--yes` skips the prompt. Without `--yes`, if input is redirected (no terminal to answer on), it refuses and exits 2.
- Right before each removal the item is re-checked. It must be Junk tier, under your profile (or under the Downloads folder, if that is on a local fixed drive), with no `.` or `..` in the path. It must still exist and still be the same kind (file or folder). It must not be a reparse point, cloud-only, or an unaddressable name. No folder on the way may be a reparse point. A failed check skips the item and says why. One failure does not stop the rest. The re-check covers type and location, not age or contents.
- The re-check and the removal are two separate calls. Someone who can already write to your profile could swap the item in between. The code notes this: there is no handle-based delete from .NET.
- Recycle Bin (default): each item goes through the Windows `SHFileOperationW` call, one at a time, with undo, no error dialogs and no progress UI. Without `--yes` it also asks Windows to warn before permanently deleting an item that is too large for the Recycle Bin (whether that warning appears in this silent mode is unverified); JunkFinder's own prompt already says oversized items are deleted permanently. With `--yes` it does not ask, so such items are **deleted permanently**. The Recycle Bin is a request: a drive set to "Don't move files to the Recycle Bin", or an item too big, is deleted permanently and the summary may still say "Moved". The summary says `Space is freed when you empty the Recycle Bin.`
- `--permanent`: JunkFinder's own bottom-up delete, no Recycle Bin, cannot be undone. It clears the ReadOnly flag first. A link or junction inside the tree is removed as a link and never entered. It does not use `Remove-Item`.
- Running-app guard: a browser cache (C1) is skipped while its browser runs (`chrome`, `msedge`, `brave`, `firefox`). An Electron cache (C1e) is skipped while a process named after its `AppData\Roaming\<App>` folder runs. Skipped items are listed as `skipped: app running`. For Edge the text adds `(Edge Startup Boost keeps it running; turn it off in edge://settings/system)`. The match is by process name only, so an app whose process has a different name than its folder is not detected.
- Summary line: `Moved N items (up to X) to the Recycle Bin; M skipped; K failed.` (`Deleted N items (up to X); ...` with `--permanent`). "Skipped" counts items the guard skipped and items that failed a re-check.
- Exit codes: 0 done (or nothing to do, or you said no), 1 at least one removal failed, 2 bad arguments or no terminal to confirm on, 3 blocked at startup (see below).

## Startup guards (exit 3)

Both print a message on stderr and exit 3 before anything is scanned.

- PowerShell is not in Full Language Mode (App Control or AppLocker): `Constrained Language Mode (App Control/AppLocker) blocks JunkFinder; run it on an unmanaged machine.`
- Running as administrator: `Run JunkFinder as a normal user, not as administrator.`

## If Windows blocks it

- **Running `junk.ps1` directly?** Files downloaded from the internet carry a "from the internet" mark. Under RemoteSigned, run `Get-ChildItem -File | Unblock-File` in the folder once. `junk.cmd` does not need this, because its Bypass ignores the mark.
- **Why `junk.cmd`?** It starts PowerShell with `-ExecutionPolicy Bypass` for that one process only. Your system setting is not changed.
- **Group Policy.** If Group Policy sets the execution policy, `-ExecutionPolicy Bypass` has no effect. With `AllSigned` the script cannot run, because it is not signed.
- **Smart App Control** may block unsigned scripts. Untested.
- **Constrained Language Mode** (App Control or AppLocker): JunkFinder prints a message and exits with code 3.

## Edge Startup Boost

Edge can keep a process running in the background, so its cache counts as in use. `clean` then skips Edge's cache and says: `skipped: app running (Edge Startup Boost keeps it running; turn it off in edge://settings/system)`. Turn off Startup boost there, close Edge, and run `clean` again.

## Rules

Paths are relative to your profile and matched case-insensitively. First match wins, in this order: deny, D, C, I, B. A folder is a candidate only if it matches; non-matching folders are searched for matches inside.

| Id | Tier | What | Gate |
|---|---|---|---|
| Deny | never | `AppData\Local\pnpm`, `.pnpm-store`, `.nuget\packages` | pnpm stores are hard-linked into projects; NuGet packages are a read-only tree |
| C1 | junk | Chrome, Edge, Brave: `Cache`, `Code Cache`, `GPUCache`, `Media Cache` in each profile under `AppData\Local\<vendor>\<product>\User Data\`, and `User Data\ShaderCache`. Firefox: `cache2` in `AppData\Local\Mozilla\Firefox\Profiles\<profile>` | none |
| C1e | junk | `AppData\Roaming\<App>\Cache`, `Code Cache`, `GPUCache` | the `<App>` folder also contains a `GPUCache` (the Chromium/Electron signature) |
| C2 | junk | children of `AppData\Local\Microsoft\Windows\WER\ReportArchive` and `ReportQueue`; files directly in `AppData\Local\CrashDumps` | modified more than 7 days ago |
| C3 | junk | direct children of `AppData\Local\Temp` | modified more than 7 days ago |
| D3 | junk | `AppData\Local\npm-cache`, `pip\Cache`, `Yarn\Cache`, `Composer`, `NuGet\v3-cache`, `go-build`; `.cargo\registry\cache` | none |
| D4 | review | `target` next to `Cargo.toml` | none |
| D5 | junk or review | `node_modules` next to `package.json` | junk if unchanged for over 30 days and a lock file is next to it (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lockb`, `bun.lock`); review otherwise |
| D6 | junk or review | `vendor` next to `composer.json` | junk if unchanged for over 30 days and `composer.lock` is next to it; review otherwise |
| I1 | junk | `.msi`, `.msix`, `.msixbundle`, `.appx`, `.appxbundle` in Downloads or one folder below it | added over 30 days ago |
| I1 | review | `.exe`, `.iso` in the same place (could be a portable app or your only copy) | added over 30 days ago |
| B1 | review | any other file of 500 MB or more (1 MB = 1,000,000 bytes) | not modified in over 180 days |

- A folder's age is the newest modification time of any file inside it. Matched folders totalling 0 bytes are not listed.
- Windows has no "date added", so I1 uses the newer of the created and modified times. A file copied in with an old timestamp does not look old.
- Hidden-folder guard: D5 and D6 never match when the first path part starts with `.` or is `AppData`. A dot-folder example is `.vscode\extensions\...\node_modules`. Per-user apps (for example under `AppData\Local\Programs`) ship a `package.json` of their own, and deleting their `node_modules` would break them.
- Incomplete contents become Review: if anything inside a matched folder could not be read or was skipped (access denied, link, junction, cloud-only file, unaddressable name), the finding drops to Review and its reason ends with `; some contents could not be read`. Its size and age are then incomplete. A plain link inside (for example pnpm junctions in `node_modules`) does the same.
- C1 and C1e are allowlists. Windows has no single cache folder, so only the listed browser and Electron caches match.

## What is never scanned, and why

These make totals a lower bound.

- Built-in skip list (relative to your profile): `Documents`, `Desktop`, `Pictures`, `Music`, `Videos`, `Favorites` (your files; Controlled Folder Access also protects them); `.ssh`, `.gnupg`, `.aws`, `.azure`, `.kube`, `AppData\Local\Microsoft\Credentials` (credentials); `AppData\Local\Microsoft\Outlook` (mail data); `AppData\Roaming\Microsoft` (Windows and Office user data, including credentials and DPAPI keys); `.config`, `.local`, `.cache` as wholes; `.rustup`, `.cargo\bin`, `scoop`, `AppData\Local\Programs` (toolchains and installed apps); `AppData\Local\Packages`, `AppData\Local\Microsoft\WindowsApps` (app packages); `.nuget\packages`, `.pnpm-store`, `AppData\Local\pnpm` (shared stores). They are not listed in the output; the footer names the main ones.
- Any top-level folder starting with `OneDrive` (`OneDrive`, `OneDrive - Contoso`): deletions sync to the cloud. Only `OneDrive*` is skipped by name. Dropbox, Google Drive and iCloud folders in the profile are scanned, and deleting there syncs to the cloud (cloud-only placeholders are still skipped).
- Links and junctions (reparse points) are never entered or counted. This avoids loops and leaving your profile.
- Cloud-only files (offline or recall-on-access placeholders) are never read or counted, so they are not downloaded. They show on the `Skipped` line as `cloud-only`.
- Names Windows cannot address safely (ending in a dot or space, or reserved device names such as `CON`, `NUL`, `COM1`) are skipped as `unaddressable name`.
- Folders that cannot be listed are recorded as `access denied`, `path too long` or `unreadable`, and the scan goes on.
- Downloads: found through its Windows known-folder setting. I1 only matches a top-level `~\Downloads`, or a Downloads folder outside the profile on a fixed drive (scanned as a second root). A Downloads folder moved elsewhere inside the profile is not matched by I1. If it was moved to a network or removable drive, it is skipped and shown as `network or removable drive` (those drives have no Recycle Bin).

Printed paths have control characters and bidi overrides replaced with `?`.

## Sizes

Sizes are logical file lengths, labelled "up to". They can overstate what you free:

- pnpm hard links count once per link.
- NTFS-compressed files take less disk than their length.
- On a Dev Drive, block-cloned copies share space.

Sizes use 1000-based units (`KB`, `MB`, `GB`, `TB`).

## Run and test

```bat
junk.cmd
```

`junk.cmd` is one line: it starts `powershell -NoProfile -ExecutionPolicy Bypass -File junk.ps1` with your arguments. Running `junk.ps1` directly works too if your execution policy allows it.

Tests run on Linux in Docker (PowerShell 7.4 with Pester 5.7.1 and PSScriptAnalyzer 1.25.0):

```sh
./test.sh              # analyzer + all tests
./test.sh Scanner      # only tests whose name contains "Scanner"
```

The analyzer checks that the script uses only Windows PowerShell 5.1 syntax. Tests tagged `Windows` are skipped on Linux. GitHub Actions runs the whole suite on `windows-latest` in Windows PowerShell 5.1 (`.github/workflows/test.yml`), which covers junctions, `\\?\` paths, ReadOnly files, the real Recycle Bin call and the language-mode guard.

`tools/probe.ps1` is a Windows-only fact finder (long paths, `SHFileOperationW`, junctions, ReadOnly, default paths). It removes its fixtures when it finishes. Its findings are in `docs/research.md` section 8.

## v1 limits

- The Mac rules for Xcode, Swift `.build` and the Mac deny/review cache lists are not ported.
- Windows PowerShell 5.1, 64-bit only. This is not enforced; the script doesn't check. Under 32-bit PowerShell a cancelled recycle may be reported as moved.
- The Recycle Bin is a request: a drive set to "Don't move files to the Recycle Bin", or items too big, are deleted permanently and the summary may still say "Moved". Only an outside Downloads folder is checked for a local fixed drive; a profile on a network drive is not checked.
- Only `OneDrive*` is skipped by name. Dropbox, Google Drive and iCloud folders in the profile are scanned, and deleting there syncs to the cloud (cloud-only placeholders are still skipped).
- These default paths are not verified on a real machine: `AppData\Local\CrashDumps`, `NuGet\v3-cache` and `go-build`. If they differ, those rules simply find nothing.
- Recycling a path longer than 260 characters is unverified. A recycle that fails is reported as failed.
- Whether Windows shows its "too large for the Recycle Bin" warning in the silent mode used here is unverified (JunkFinder's own prompt already warns).
- Smart App Control with `junk.cmd` is untested.
- Scan time has not been measured on a large profile. The scan is a PowerShell loop; the code notes it may need to move into C# if it proves slow.
- App detection for the running-app guard is by process name only.
