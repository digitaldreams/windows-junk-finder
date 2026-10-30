# JunkFinder for Windows: tasks

Windows 11 port of the macOS JunkFinder (`../JunkFinder`, Swift). It ships as one unsigned `junk.ps1` for Windows PowerShell 5.1 plus a `junk.cmd` launcher, and runs as a normal user against `%USERPROFILE%`. `junk` lists junk; only `junk clean` removes anything (T6), Junk tier only, after confirmation.

References:
- `docs/research.md`: the Windows limits, security and PowerShell constraints. §7 is the plan.
- `../JunkFinder` (`README.md`, `docs/how-it-works.md`, `Sources/JunkCore/*.swift`): the behaviour to port, including output format, tiers, reasons and clean flow. Where it makes sense, match it.
- Where this file differs from either one, this file wins. Differences are listed under "Deviations".

**Loop:** for each `todo` task, in order:
1. `windows-dev` implements the task.
2. `windows-reviewer` reviews it.
3. FAIL: the findings go back to `windows-dev`, at most 2 fix rounds. After that, stop and ask the human.
4. PASS: run `git add -A` and mark the task `done`.

After T4 and T6, the main session runs a break review (global CLAUDE.md) before the task is marked `done`. Tasks marked **Human** need a run on real Windows; agents prepare it and stop.

Statuses: `todo` · `in-progress` · `review` · `done` · `blocked`

## Layout

```
junk.ps1              # everything; dot-sourceable, Main runs only when invoked directly
junk.cmd              # powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0junk.ps1" %*
tests/*.Tests.ps1     # Pester 5
tools/probe.ps1       # T2, Windows-only fact finder
test.sh               # Docker pwsh + Pester 5 + PSScriptAnalyzer (5.1 syntax)
```

Rules for the code (all tasks):
- **PowerShell 5.1 syntax only:** no `??`, ternary, `&&`/`||`, `-Parallel`, `EnumerationOptions` or `::new()` on types missing from .NET 4.8. `test.sh` enforces this with `PSUseCompatibleSyntax` targeting 5.1.
- **Tests run on Linux pwsh 7 in Docker.** Item paths are relative to home, joined with `\` by our own code, never `[IO.Path]::Combine`. OS-specific calls go through tiny helpers so tests can run on Linux:
  - `\\?\` prefix: added only when `$env:OS -eq 'Windows_NT'`.
  - Recycle Bin: `SHFileOperationW`.
  - Elevation check.
  - Process list.
  - Downloads known folder.
- **Pure logic takes an injected `$Now`.** Never call `Get-Date` inside it.

## Rule table (Windows v1)

Paths are relative to `%USERPROFILE%`, and matching is case-insensitive. First match wins, in this order: deny → D → C → I → B.

| Id | Tier | Match | Reason |
|---|---|---|---|
| Deny | never | anything under the skip list (T4); pnpm store; `.nuget\packages` | — |
| C1 | junk | Chromium caches (`Cache`, `Code Cache`, `GPUCache`, `Media Cache`) under `AppData\Local\{Google\Chrome, Microsoft\Edge, BraveSoftware\Brave-Browser}\User Data\<Profile>\`; `User Data\ShaderCache`; Firefox `AppData\Local\Mozilla\Firefox\Profiles\<p>\cache2` | browser cache; close the browser before deleting |
| C1e | junk | `AppData\Roaming\<App>\{Cache, Code Cache, GPUCache}` when the `<App>` folder also contains `GPUCache` (Chromium/Electron signature) | app cache; quit the app before deleting |
| C2 | junk | direct children of `AppData\Local\Microsoft\Windows\WER\{ReportArchive, ReportQueue}`, and files in `AppData\Local\CrashDumps`, modified > 7 d ago | crash report older than 7 days |
| C3 | junk | direct children of `AppData\Local\Temp` modified > 7 d ago | temp file older than 7 days |
| D3 | junk | `AppData\Local\{npm-cache, pip\Cache, Yarn\Cache, Composer, NuGet\v3-cache, go-build}`, `.cargo\registry\cache` | package manager download cache; re-downloaded on demand |
| D4 | review | dir `target` with sibling `Cargo.toml` | Rust build output next to Cargo.toml; rebuilt by cargo |
| D5 | junk / review | dir `node_modules` with sibling `package.json`. Junk when stale (> 30 d) **and** a lock file is next to it (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lockb`, `bun.lock`); Review otherwise | Mac reasons |
| D6 | junk / review | dir `vendor` with sibling `composer.json`. Same gate, lock file `composer.lock` | Mac reasons |
| I1 | junk | file in Downloads (depth ≤ 2) with extension `msi`, `msix`, `msixbundle`, `appx`, `appxbundle`, older than 30 d | installer added over 30 days ago |
| I1 | review | same, with extension `exe` or `iso` | installer or disk image; make sure it isn't your only copy |
| B1 | review | file ≥ 500 MB (1 MB = 1,000,000 B) modified > 180 d ago, not matched above | large file (500 MB or more), not modified in over 180 days |

Shared gates:
- **Directory age:** a directory's `modified` is the newest `LastWriteTimeUtc` of any file inside it; empty directories fall back to their own time.
- **Hidden-folder guard:** D5 and D6 never match when the first path component starts with `.` or is `AppData`. Apps installed per user (e.g. `AppData\Local\Programs\<app>\resources\app\node_modules`) ship a `package.json`, and deleting their `node_modules` breaks the app.
- **I1 age:** Windows has no "date added". I1 age uses the newer of `CreationTimeUtc` and `LastWriteTimeUtc`; an old timestamp copied from the server can't make a fresh download look old.

## Deviations (intended, not bugs)

- **Mac rules not ported:**
  - D1 (Xcode): no Windows equivalent.
  - `.build`/`Package.swift` in D5: Swift on Windows is rare.
  - C1r and the Mac deny list: Mac-only paths.
- **C1 is an allowlist.** Windows has no single `Library/Caches` folder, so C1/C1e match only the listed browser and Electron caches, not "every child of a cache folder".
- **New Windows rules:** C3 (user temp) and C1e (Electron caches).
- **Sizes are logical** (`FileInfo.Length`), with no hard-link dedup. The report says "up to" (research §2 Sizes); the Mac version uses allocated bytes, hard links once.
- **No volume check.** A folder on another volume can only be reached through a reparse point, which is skipped anyway.
- **I1 `.exe` is Review:** it may be a portable app, not an installer.

## Decisions (approved by the human, 2026-10-30)

1. **Recycle Bin and `--yes`.** Decided:
   - Interactive runs pass `FOF_WANTNUKEWARNING`, so Windows asks before permanently deleting an item too big for the bin. The user is at the screen to answer.
   - `--yes` runs drop that flag, because a modal dialog would hang an unattended run. The `--yes` help line and the README say that oversized items are then deleted permanently.
   - Rejected for v1: skipping items larger than the bin (needs the volume GUID lookup and more code).
2. **CI on GitHub `windows-latest`** (T7): approved. Repo `digitaldreams/windows-junk-finder` is **public** (the human created and pushed it, 2026-10-30).

---

## T1 Scaffold
- Agent: windows-dev · Reviewer: windows-reviewer
- Status: done

- `git init`; `.gitignore` (empty unless needed).
- `junk.ps1` as described in Layout. It starts with:
  - `Set-StrictMode -Version 2`
  - `$ErrorActionPreference = 'Stop'`
  - a `Main` that prints a placeholder line.
  - a guard so that dot-sourcing (`. .\junk.ps1`) loads the functions without running `Main`.
- `junk.cmd` as described in Layout. It passes arguments through and returns the script's exit code.
- `test.sh`:
  - Runs `mcr.microsoft.com/powershell` (pinned tag) with the repo mounted read-only at `/src`.
  - Installs Pester 5 and PSScriptAnalyzer.
  - Runs `Invoke-ScriptAnalyzer` with `PSUseCompatibleSyntax` targeting 5.1. Any finding fails the run.
  - Runs `Invoke-Pester /src/tests`.
  - Extra args pass through as a test name filter.
  - Exits non-zero on any failure.
  - `ponytail:` cache the module install in a named volume if the run is slow.
- `tests/Smoke.Tests.ps1`: dot-sources `junk.ps1` and asserts that one function exists.

Acceptance: `./test.sh` passes. A deliberate `$a ?? $b` in `junk.ps1` makes it fail; remove it again afterwards.

## T2 Windows probe (Human)
- Agent: windows-dev (writes it) · Run: human on Windows 11 · Reviewer: windows-reviewer
- Status: done (results in research §8)

This task answers research §8 before code depends on the answers. `tools/probe.ps1` creates fixtures under `$env:TEMP\junk-probe`, removes them at the end, and prints one `PASS`/`FAIL`/`INFO` line per check:
1. `\\?\`-prefixed .NET calls work in 5.1: `[IO.Directory]::Exists`, `EnumerateFileSystemInfos`, `[IO.File]::Delete` and `DirectoryInfo.Delete`. This is the riskiest assumption: legacy path handling may reject them.
2. Paths longer than 260 characters work with `\\?\`, and without it (print `LongPathsEnabled`).
3. `SHFileOperationW` (via Add-Type) can recycle a plain path; a `\\?\` path is also tried.
4. `mklink /J` junction: `Attributes` has `ReparsePoint`; deleting the junction leaves its target intact.
5. A ReadOnly file: delete fails, then succeeds after clearing ReadOnly.
6. Language mode, elevation check result, and `[Console]::IsInputRedirected`.
7. Default paths that exist on this machine: Composer, Yarn, `CrashDumps`, the Downloads known folder.

Not run automatically: `FOF_WANTNUKEWARNING` dialog behaviour. The human tests that by hand with an item bigger than the bin.

Acceptance:
- The probe passes the analyzer, and its Pester tests (Linux) cover only the output formatting.
- The human pastes the output.
- The main session records the answers in research §8. If check 1 fails, `\\?\` handling moves into the Add-Type C# and T4/T6 are updated **before** they start.

## T3 Rule matcher (pure logic, TDD)
- Agent: windows-dev · Reviewer: windows-reviewer
- Status: done

`Get-JunkMatch -Item $item -Now $now` returns `$null` or `[pscustomobject]@{Category; Tier; RuleId; Reason}`.
- Item: `Path` (relative to home, `\`-separated), `Kind` (`file`/`dir`), `Siblings` (names), `Size` (bytes), `Modified` (UTC), `Created` (UTC).
- Categories, in report order: `Caches & logs` (C*), `Dev junk` (D*), `Old installers` (I1), `Big files` (B1).
- Rules exactly as in the rule table.

Acceptance (tests first; each one must fail before it is implemented):
- Every rule has one positive and one negative test, and every shared gate has a test.
- Boundaries:
  - WER/temp 6 d vs 8 d
  - I1 29 d vs 31 d (and creation time newer than write time)
  - D5/D6 29 d vs 31 d
  - B1 499 MB vs 500 MB, and 179 d vs 181 d
- Precedence: a `node_modules` holding a 2 GB file → D5 only; `AppData\Local\npm-cache` → D3, not C3.
- Case: `NODE_MODULES`, `appdata\local\TEMP\x` both match.
- `target` with only `pom.xml` → `$null`. `AppData\Local\Programs\x\resources\app\node_modules` with `package.json` → `$null`. `C1e` without a `GPUCache` sibling → `$null`.

## T4 Scanner
- Agent: windows-dev · Reviewer: windows-reviewer
- Status: done
- Break review: #1 fixed: an outside Downloads on a network/removable drive (no Recycle Bin) is not scanned; recorded as skipped "network or removable drive".
- Review notes: a young dir under Temp/WER is not descended (a B1 inside it is missed); any inner skip (incl. pnpm junctions) downgrades a match to Review.

`Invoke-JunkScan -Root $home -Now $now [-ExtraRoot $downloads]` returns `@{Findings; Skipped}`. A finding is the item plus its match.

**Walk:**
- A hand-written depth-first loop using `DirectoryInfo.EnumerateFileSystemInfos()`, with `\\?\` on Windows. Never `Get-ChildItem -Recurse`.
- Each folder's enumeration is wrapped in its own try/catch, so one unreadable folder never stops the scan.

**Never descend or count:**
- An entry whose `Attributes` has `ReparsePoint`. Skip it silently: the profile ships many legacy links.
- An entry with `Offline` (0x1000), `RECALL_ON_OPEN` (0x40000) or `RECALL_ON_DATA_ACCESS` (0x400000). Record it as `cloud-only`.
- A name ending in `.` or a space, or a reserved device name (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`, with or without an extension). Record it as `unaddressable name`.
- **Skip list** (never descend):
  - Top level: `OneDrive*`, `Documents`, `Desktop`, `Pictures`, `Music`, `Videos`, `Favorites`, `.ssh`, `.gnupg`, `.aws`, `.azure`, `.kube`, `.config`, `.local`, `.cache`, `.rustup`, `.cargo\bin`, `.nuget\packages`, `.pnpm-store`, `scoop`.
  - Under `AppData`: `Local\Packages`, `Local\Microsoft\WindowsApps`, `Local\Microsoft\Outlook`, `Local\Microsoft\Credentials`, `Local\Programs`, `Local\pnpm`, `Roaming\Microsoft`.

**Siblings:** collected for `target`, `node_modules`, `vendor` and the C1e app folder.

**Matched directories:**
- Sized by summing `Length` of every file inside, using the same reparse/cloud/name rules.
- `Modified` is the newest file inside, collected during that same walk.
- The walk does not descend further into the match.
- A match with size zero is dropped.

**Errors:**
- `UnauthorizedAccessException` → `access denied`; `PathTooLongException` → `path too long`; anything else → `unreadable`.
- Only the top-most failing path is recorded, once.

**Downloads:**
- Resolved from `HKCU\...\Explorer\User Shell Folders`, value `{374DE290-123F-4565-9164-39C4925E467B}`, with environment variables expanded.
- When it is outside home, it is scanned as `-ExtraRoot` for I1 only. Its item paths are prefixed `Downloads\`.

Acceptance: integration tests with fixtures under `$TestDrive` on Linux. A symlink there gets `ReparsePoint` in .NET Core, so the skip path is really tested.
- A symlink to an outside dir and a symlink loop are not followed, and the scan ends. A symlink to a `.msi` in Downloads → no finding.
- `node_modules\a\node_modules\b` with `package.json` → one finding, counted once.
- A `node_modules` holding a 600 MB sparse file (`SetLength`) → one D5 finding, no B1 for the inner file.
- A skip-list dir with junk inside → no findings.
- `chmod 000` dir → recorded as `access denied`, and the scan continues. Restore permissions in `AfterEach`.
- A dir named `node_modules.` (trailing dot) next to a real one → recorded as `unaddressable name`; only the real one is found.
- An empty matched dir → no finding. A dir's `Modified` equals its newest file's time.
- Classifier unit test with injected exceptions.

## T5 Report, CLI and startup guards
- Agent: windows-dev · Reviewer: windows-reviewer
- Status: done
- Verify on real Windows (T7/T8): the CLM guard message via `$host.UI.WriteErrorLine` prints under Constrained Language Mode (exit 3 holds either way).

**`Format-JunkReport $result $now`:**
- Port the Mac `render`: sections in category order, sorted by size descending; paths shown as `~\...`; 1000-based sizes (port `formatSize` and its boundaries); age `modified N d ago`; rule id and reason.
- Totals: "Junk (reclaimable)" and "Review (check before deleting)", each prefixed "up to".
- One "Skipped" line, grouped by kind.
- Footer:
  - Sizes are logical; NTFS compression, pnpm hard links and Dev Drive block clones can make totals overstate.
  - Not scanned by design: OneDrive, Documents, Desktop, Pictures, Music, Videos, app packages, credentials.

**`ConvertTo-SafeText`:** every printed path replaces these characters with `?`:
- C0 controls and DEL
- C1 controls U+0080–U+009F
- bidi overrides U+202A–U+202E and U+2066–U+2069

**`Main`:** sets the UTF-8 console encoding, runs the startup guards, scans home, prints the report, and exits 0.

**Startup guards** (exit 3, one line on stderr each):
- Not `FullLanguage` → "Constrained Language Mode (App Control/AppLocker) blocks JunkFinder; run it on an unmanaged machine."
- Elevated → "Run JunkFinder as a normal user, not as administrator."

Acceptance (TDD):
- Render tests on a fixed result assert exact output: section order, sorting, totals, the size boundaries (999 KB / 1.0 MB, 999 MB / 1.0 GB, 99,950,000 → "100 MB"), the skipped line and the footer.
- The safe-text test covers `\n`, ESC, U+009B and U+202E.
- Guards are tested by injecting the language mode and the elevation flag.

## T6 `junk clean <section>...`
- Agent: windows-dev · Reviewer: windows-reviewer
- Status: done
- Break review: no real breaks found. Accepted: recheck-to-remove race (same-user only); `--yes` deletes items too big for the bin (Decision 1).
- Review notes for T7/T8: Windows-only junction delete branch (`Directory.Delete(p,$false)`) needs a `Windows`-tagged test; 32-bit PowerShell would misread `fAnyOperationsAborted` (struct packing), so only 64-bit is supported.
- T2 answers: `\\?\` works for .NET calls; `SHFileOperationW` rejects `\\?\` (rc 0x7C), so recycle takes the plain path.

Port Mac T8/T9 behaviour (`../JunkFinder/Sources/JunkCore/Cleaner.swift`), with these changes:

**Arguments:**
- Syntax: `junk clean <section>... [--yes] [--permanent]`.
- Sections: `caches` → C1, C1e; `logs` → C2; `temp` → C3; `dev` → D3; `installers` → I1 Junk; `node_modules` → D5 Junk; `vendor` → D6 Junk.
- `big` is refused with "Big files are Review only; delete them by hand".
- Unknown or missing section → usage message, exit 2.

**Plan (pure):** `Get-CleanPlan $result $sections $runningProcessNames` returns `remove` and `skipped`.
- Only Junk-tier findings are selected.
- Running-app guard:
  - C1 is skipped when its browser runs: `chrome`, `msedge`, `brave` or `firefox`.
  - C1e is skipped when a process whose name equals the `<App>` folder name runs (case-insensitive).
  - The skip reason is "skipped: app running".
  - For Edge, the reason adds "(Edge Startup Boost keeps it running; turn it off in edge://settings/system)".
  - `ponytail:` name match only. Map Teams/Discord process names if real runs show misses.

**Confirmation:**
- `[Console]::IsInputRedirected` without `--yes` → refuse, exit 2.
- Prompt: `Move N items (up to X GB) to the Recycle Bin? Items too large for it are deleted permanently. [y/N]`.
- With `--permanent`: `Permanently delete N items (up to X GB)? This cannot be undone. [y/N]`.
- Anything but `y`/`yes` aborts with exit 0.

**Re-check each item right before removing it:**
- It still exists.
- It is not a reparse point, and no component between home and the item is one.
- It is still under its root.
- Its name is still addressable.
- A failed check skips the item and reports it.

**Removal:**
- **Recycle:** `SHFileOperationW` via Add-Type with a tiny C# 5 class, called on the plain absolute path (double-null-terminated). Flags: `FOF_ALLOWUNDO|FOF_NOERRORUI|FOF_SILENT|FOF_NOCONFIRMATION`, plus `FOF_WANTNUKEWARNING` unless `--yes` (decision 1). A non-zero return code or `fAnyOperationsAborted` counts as failed.
- **`--permanent`:** our own bottom-up delete over `\\?\` paths. It clears ReadOnly before each delete, removes a reparse point as a link without descending into it, and never uses `Remove-Item`.
- One item at a time; an error on one item is reported and the rest continue.

**Summary:** `Moved N items (up to X GB) to the Recycle Bin; M skipped; K failed.` Exit 0 when nothing failed, 1 otherwise. All printed paths go through `ConvertTo-SafeText`.

Acceptance (TDD for plan, args and re-checks; fixtures on Linux):
- Plan: each section selects exactly its rules; Review findings are never selected; `big` is refused; running browser/app → skipped with reason.
- Args: none, unknown, `big`, flags in any order, all `--yes`/`--permanent` combinations.
- Re-checks:
  - An item replaced by a symlink → not removed.
  - A parent swapped for a symlink to a dir outside the root → nothing outside the root is touched.
  - An item deleted before removal → reported as skipped, no error.
- Permanent delete:
  - Removes a fixture tree that contains a ReadOnly file.
  - A symlink inside the tree is removed but its target survives.
- Recycle path: unit-tested with the `SHFileOperationW` helper mocked. The real call is covered by T7/T8.
- No test touches anything outside `$TestDrive`.

## T7 CI on real Windows
- Agent: windows-dev · Reviewer: windows-reviewer
- Status: review (CI run 41055797773: 293 passed, 1 failed; the failing child-process CLM test was removed: `__PSLockdownPolicy` does not force CLM on the runner. The CLM runspace test passes on real 5.1.)

`.github/workflows/test.yml` runs on `windows-latest` with `shell: powershell` (5.1). The tests themselves must then load on 5.1: fix PS7-only calls in `tests/` (e.g. 3-argument `Join-Path` in `Smoke.Tests.ps1`, flagged in T1 review). Module downloads in `test.sh` have no checksum (T1 review; accepted, dev-only).
1. Install Pester 5 (`-Force -SkipPublisherCheck`).
2. Run the tests.
3. Run Windows-only tests tagged `Windows`, skipped on Linux:
   - `mklink /J` junction skip and recheck
   - `\\?\` paths and a long (> 260 characters) `node_modules` path
   - ReadOnly delete
   - a real `SHFileOperationW` recycle of one tiny fixture: assert the return code is 0 and the source is gone. The test leaves the item in the runner's bin.
   - the CLM guard via `$ExecutionContext.SessionState.LanguageMode` in a constrained runspace

## T8 Real run, README and how-it-works (Human)
- Agent: windows-dev (docs) · Run: human on Windows 11 · Reviewer: windows-reviewer
- Status: todo

**Human:**
1. Run `junk.cmd` on a real profile and note the wall time. If it's over about 5 min, mark `ponytail:` on the hot loop and propose moving it into C#.
2. Spot-check 3 sizes against Explorer's "Size" (within 1%).
3. Run `junk.cmd clean temp` once with the prompt.
4. Note any Smart App Control, Defender/AMSI or Controlled Folder Access block.

**Docs:**
- `README.md`: port the Mac landing page. Include:
  - Setup: `Unblock-File`, why `junk.cmd`, that a Group Policy enforcing AllSigned blocks it, and the Smart App Control limit.
  - Recycle Bin vs `--permanent`.
  - The Edge Startup Boost note.
- `docs/how-it-works.md`: the rule table, the skip list and why, the re-checks, exit codes (0/1/2/3).

Surprises are reported to the human as findings. They are not fixed silently.
