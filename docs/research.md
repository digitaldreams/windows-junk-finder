# Windows 11 port: limits, security, PowerShell constraints

Target: Windows PowerShell 5.1 (inbox on Windows 11), one unsigned `.ps1` plus a `junk.cmd` launcher, run as a normal user against `%USERPROFILE%`.

**Verdict.** The port is feasible, but three Windows traps are worse than anything on the Mac side:

1. **Reparse points.** Junctions, symlinks and cloud placeholders are all reparse points. Windows PowerShell's `Get-ChildItem -Recurse` follows junctions, and the profile ships with self-referencing legacy junctions. The scanner must use its own recursion and skip every reparse point. That one rule also prevents the infinite loop, the cloud-file hydration and following a link outside home.
2. **The Recycle Bin is a request, not a guarantee.** `FOF_ALLOWUNDO` silently turns into a permanent delete when the item is too big for the bin, or when the drive has no bin (removable or network). `FOF_NOCONFIRMATION` auto-accepts that permanent delete.
3. **The script can be blocked before it runs.** Execution policy (Restricted by default on client Windows), Mark of the Web, Group Policy, App Control/AppLocker (forces Constrained Language Mode, where Add-Type is blocked) and Smart App Control (blocks unsigned scripts) can each stop an unsigned `.ps1`.

The fixes are: skip all reparse points, use `\\?\` paths for every recheck and delete, refuse to run outside FullLanguage mode, and treat "moved to Recycle Bin" as best effort, which the prompt and docs say plainly.

---

## 1. PowerShell constraints

| Constraint | Fact | Consequence for us |
|---|---|---|
| Version | Windows 11 ships Windows PowerShell 5.1 (.NET Framework 4.8). PS 7 is opt-in. | No `??`, ternary, `&&`/`\|\|`, `EnumerationOptions` or `-Parallel`. CI runs PSScriptAnalyzer `PSUseCompatibleSyntax` against 5.1. |
| Add-Type C# | 5.1 compiles C# 5 only. `-CompilerOptions` is not available on 5.1. Add-Type runs `csc.exe`, which writes to disk (`%TEMP%`), and the first run is slow. | Keep the C# tiny (one `SHFileOperationW` P/Invoke). Expect about 1–2 s of startup. |
| Execution policy | The client default is **Restricted**. Under RemoteSigned, a downloaded script also needs a signature unless its Mark of the Web (`Zone.Identifier` ADS) is removed. `-ExecutionPolicy Bypass` affects only that process. A Group Policy setting at MachinePolicy/UserPolicy scope wins over the command-line flag. | `junk.cmd` runs `powershell -NoProfile -ExecutionPolicy Bypass -File junk.ps1`. If a GPO enforces AllSigned we cannot run. The README says so and suggests `Unblock-File`. |
| Constrained Language Mode | When App Control (WDAC) or AppLocker enforces, PowerShell switches to CLM by itself. CLM blocks Add-Type ("arbitrary types defined in different languages") and allows only an approved list of .NET types, so static calls like `[IO.Directory]::...` may be blocked as well. | On the first line, check `$ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage'` and exit with a clear message (code 3). Don't try to work around it: locked-down corporate machines are out of scope. |
| Smart App Control (Win 11) | Blocks unknown or unsigned scripts. It is a separate mechanism from execution policy, and changing the policy doesn't bypass it. The CodeIntegrity Operational event log names the blocked file. | Unsigned `.ps1` may be blocked on SAC-enabled machines. Documented as a known limit. Code signing is a later item. |
| `Get-ChildItem -Recurse` | In Windows PowerShell it **follows junctions and symlinks to directories**. It is also slow on big trees (one report: about 700k files was "too slow"). `-Include` is slower still. | Never use it for the scan. Recurse by hand with `DirectoryInfo.EnumerateFileSystemInfos()`, checking `Attributes` before descending. |
| `Remove-Item -Recurse` | Microsoft's own docs say `-Recurse` "has a known issue". Issue #16664: `-WhatIf` still removes links. It fails on read-only files without `-Force`. | Don't use Remove-Item for `--permanent`. Write our own bottom-up delete that never descends into a reparse point (it removes the link only), clears ReadOnly and uses `\\?\` paths. |
| Console encoding | 5.1 writes non-ASCII through the OEM/ANSI code page, so characters it can't represent print as `?`. Redirection (`>`) writes UTF-16LE. | Set `[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)` at the start. Keep `safe()` for control characters. |
| Pester | Windows ships Pester 3.4.0 inbox, and `Update-Module` can't upgrade it. Pester 5 needs `Install-Module Pester -Force -SkipPublisherCheck`. Pester 5 runs on 5.1. | Tests use Pester 5 syntax. `test.sh` installs it in the Docker pwsh image, and CI installs it on Windows. |

## 2. Windows filesystem limits

### Reparse points (most important)
- `%USERPROFILE%` contains compatibility junctions (`Application Data`, `Local Settings`, `My Documents`, `AppData\Local\Application Data`, ...), some of which point back at their own parent. Only a **deny "List folder" ACE for Everyone** keeps scanners from looping. Forum reports show loops 24 levels deep once that ACE is gone.
- Other reparse points in a home folder: symlinks, OneDrive/cloud placeholders, `AppData\Local\Microsoft\WindowsApps` execution aliases, **pnpm's `node_modules` (junctions on Windows)**, and WOF-compressed files.
- **Rule:** if `Attributes -band ReparsePoint`, the scanner neither descends nor counts it, the recheck refuses it if it is the item or anywhere on the item's path, and the deleter removes the link itself and never its target.
- Cost: WOF-compressed files in home are not counted (rare outside `C:\Windows`).

### Cloud files (OneDrive Files On-Demand)
- A placeholder carries `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS` (0x400000), `RECALL_ON_OPEN` (0x40000) and/or `OFFLINE` (0x1000). Microsoft's filter guidance says not to read these files, because reading triggers hydration. Enumeration alone reads only metadata. That is not explicitly documented, so we skip the whole tree anyway.
- Windows 11 often redirects Desktop, Documents and Pictures into OneDrive through Known Folder Move.
- **Rule:** skip any `OneDrive*` top-level folder. Any file with those attributes is recorded as "cloud-only" and not counted. Being a reparse point, it is already skipped.

### Path length
- MAX_PATH is 260. Long paths need **both** `LongPathsEnabled=1` (HKLM, off by default) **and** a `longPathAware` app manifest. .NET Framework 4.6.2+ supports long paths by default. Whether `powershell.exe`'s manifest opts in is **unverified**. Deep `node_modules` trees regularly go past 260.
- The `\\?\` prefix bypasses MAX_PATH and Win32 normalization, but only works with absolute paths.
- **Rule:** every .NET file call goes through `\\?\C:\Users\...` full paths. This works without the registry key on .NET 4.6.2+.

### Name normalization (security)
- Win32 strips trailing dots and spaces from path components, so `foo.` resolves to `foo`. Reserved device names (`CON`, `NUL`, `AUX`, `COM1`, ...) are special. WSL, git and `\\?\` can all create such names.
- Attack: a folder named `node_modules.` (or `node_modules ` with a trailing space) next to a real `node_modules`. Without `\\?\`, a check or delete aimed at one can land on the other.
- **Rule:** use `\\?\` paths throughout, *and* skip (and record as unaddressable) any name ending in `.` or a space, or matching a reserved device name. That is cheap and needs no reasoning about edge cases.

### Files in use
- Windows has no unlink-while-open. A file opened without `FILE_SHARE_DELETE` can't be deleted or renamed, and **a directory can't be renamed while any descendant has an open handle**.
- Recycling a folder on the same volume is a rename, so a busy cache folder fails as a whole (good: nothing partial). A permanent recursive delete can leave the item partly deleted. That is acceptable for the Junk tier: the thing regenerates either way.
- Chromium and Electron keep their cache files open, so deleting the cache of a running browser fails anyway. The running-app guard mainly keeps the output tidy.

### Read-only and hidden attributes
- Git pack files (`.git\objects\pack`) and some npm files are ReadOnly. Win32 refuses to delete them.
- **Rule:** the permanent deleter clears `ReadOnly` before each delete. Recycling through the shell handles it.

### Sizes
- `FileInfo.Length` is the logical size. The allocated size needs `GetCompressedFileSizeW` (it returns the compressed or sparse size), and that's one P/Invoke per file.
- No hard-link dedup: .NET Framework exposes no file ID without P/Invoke. **The pnpm store hard links into every project's `node_modules`**, so totals can double-count.
- ReFS Dev Drive block cloning shares clusters between files, so per-file totals overstate.
- **Rule for v1:** use logical `Length`. The report says "up to" and explains NTFS compression, pnpm hard links and Dev Drive clones. `ponytail:` switch to GetCompressedFileSizeW if compressed folders give clearly wrong totals.

### Case
- NTFS is case-insensitive by default, but WSL can turn on per-directory case sensitivity. Rule matching uses PowerShell's default case-insensitive `-eq`/`-like`.

## 3. Recycle Bin

| Fact | Source quality |
|---|---|
| The bin is per volume and per user SID (`X:\$Recycle.Bin\<SID>`). Its default maximum is about 5% of the volume. A custom limit is stored as `MaxCapacity` (MB) under `HKCU\...\Explorer\BitBucket\Volume\{GUID}`, and that key is usually missing until the user changes it. | Community sources plus an Old New Thing post. Exact default **unverified**. |
| An item larger than the bin is **deleted permanently**. When the bin fills, the oldest items are purged. | Community, consistent across sources. |
| `FOF_ALLOWUNDO` is a request. Removable, network and non-NTFS drives get a permanent delete. Neither the return value nor `fAnyOperationsAborted` reliably tells which happened. | Forum. Microsoft's docs are silent. |
| `FOF_NOCONFIRMATION` auto-answers "too big, delete permanently?" with yes. `FOF_WANTNUKEWARNING` brings that one warning back (as a dialog). | Win SDK header comment; no Learn page. |
| `IFileOperation` with `FOFX_RECYCLEONDELETE` is Microsoft's preferred API, but calling it from PowerShell needs a COM interop declaration, a lot more C#. | Learn. |
| `Microsoft.VisualBasic.FileIO.FileSystem.DeleteDirectory(..., OnlyErrorDialogs, SendToRecycleBin)` needs no compile, but **shows modal error dialogs** (locked file, etc.), which hangs a `--yes` run. | Learn. |

**Recommendation:** use `SHFileOperationW` via Add-Type with `FOF_ALLOWUNDO | FOF_NOERRORUI | FOF_SILENT | FOF_NOCONFIRMATION | FOF_WANTNUKEWARNING`, on a plain absolute path (SHFileOperation takes a double-null-terminated list). That means no dialogs except the "too big for Recycle Bin" warning, which is the one we want. Alternatively, refuse to recycle items larger than `MaxCapacity`, or 5% of the volume when that key is missing, unless `--permanent` is passed. That needs the volume GUID lookup and more code, so it is kept for later.

## 4. Other security mechanisms

- **Controlled Folder Access (Defender):** blocks untrusted apps, **including `powershell.exe`, which can't safely be allowlisted**, from changing protected folders (Documents, Desktop, Pictures, Videos, Music, Favorites, plus anything the user adds). We skip all the default ones. If a user protects `Downloads` or a project folder, deletes there fail with access denied, show up as "failed", and nothing breaks. Issue PowerShell#21546 also reports CFA hanging PowerShell.
- **AMSI/Defender:** every script block goes through AMSI. Add-Type with `DllImport` of `shell32!SHFileOperationW` isn't a known detection pattern (detections target `VirtualProtect`/`GetProcAddress` patching), but no vendor guarantees it. **Unverified. Watch for it during the Windows test.**
- **Elevation:** not needed, since every target sits in the user's own profile. Running elevated gives no benefit and widens the reach (bypasses some user-level ACLs). **Rule:** refuse to run elevated (`WindowsPrincipal.IsInRole(Administrator)` on the current token returns true only when actually elevated).
- **Process detection:** `Get-Process` names work without admin rights. `.Path` is `$null` for elevated or protected processes, so match on `ProcessName` only. Edge's **Startup Boost** keeps `msedge.exe` running after the window closes, and `msedgewebview2.exe` belongs to Teams, Outlook and Widgets. Expect Edge caches to be "skipped: app running" most of the time; the output tells the user to turn off Startup Boost.
- **Logging:** enterprise machines may log script blocks and transcripts. We print paths only, never contents.

## 5. Where things live (Windows defaults)

| What | Path (`%LOCALAPPDATA%` = `~\AppData\Local`) | Confidence |
|---|---|---|
| User temp | `%LOCALAPPDATA%\Temp` (`%TEMP%`) | High |
| Chrome / Edge / Brave cache | `<Vendor>\...\User Data\<Profile>\{Cache, Code Cache, GPUCache, Media Cache}`, `User Data\ShaderCache`, `Edge\User Data\component_crx_cache` | Medium (blogs, consistent) |
| Firefox cache | `%LOCALAPPDATA%\Mozilla\Firefox\Profiles\<p>\cache2` (the profile itself is in Roaming) | Medium |
| Electron apps (Slack, Discord, VS Code, Teams classic) | `%APPDATA%\<App>\{Cache, Code Cache, GPUCache}` | Low: no vendor docs, a common pattern |
| npm | `%LOCALAPPDATA%\npm-cache` (npm 7-era docs wrongly said `%APPDATA%`; fixed upstream) | High (npm docs) |
| pip | `%LOCALAPPDATA%\pip\Cache` | High |
| Composer | `%LOCALAPPDATA%\Composer` | **Unverified** (`composer config cache-dir`) |
| Yarn classic | `%LOCALAPPDATA%\Yarn\Cache` | **Unverified** (`yarn cache dir`) |
| pnpm store | `%LOCALAPPDATA%\pnpm\store` or `<drive>:\.pnpm-store`; hard-linked into projects | Low. **Don't clean**: projects link into it |
| NuGet HTTP cache / Go build / Cargo | `%LOCALAPPDATA%\NuGet\v3-cache`, `%LOCALAPPDATA%\go-build`, `~\.cargo\registry\cache` | Medium |
| WER reports | `%LOCALAPPDATA%\Microsoft\Windows\WER\{ReportArchive,ReportQueue}` | High (forensics refs, MS blog) |
| Crash dumps | `%LOCALAPPDATA%\CrashDumps` (the LocalDumps default) | **Unverified** |
| Downloads | Known folder `{374DE290-123F-4565-9164-39C4925E467B}` under `HKCU\...\Explorer\User Shell Folders` (REG_EXPAND_SZ). **Can be redirected** off the profile (D:, OneDrive). | High |

What Windows already does: Storage Sense removes unused app temp files, by default only when disk space is low, and **leaves browser caches alone**. Disk Cleanup is deprecated in favor of Storage Sense. JunkFinder adds value with dev junk, browser and Electron caches, old installers and big stale files, not with `%TEMP%` alone.

## 6. Testing without a Windows box

| Layer | Where | Covers |
|---|---|---|
| Pure logic (rules, report, args, plan) | Docker `mcr.microsoft.com/powershell` (pwsh 7, Linux) + Pester 5 | Most behavior |
| Scanner and recheck on real files | Same container. .NET on Linux sets `ReparsePoint` on symlinks, so the reparse-skip path is really tested. | Reparse skip, siblings, skip list, sizing |
| 5.1 syntax | PSScriptAnalyzer `PSUseCompatibleSyntax` targeting 5.1 | PS7-only syntax slipping in |
| Real Windows (5.1, junctions via `mklink /J`, ReadOnly, `\\?\`, long paths, `SHFileOperationW`, CLM detection) | **GitHub Actions `windows-latest`, `shell: powershell`**, with Pester 5 installed in a workflow step | Everything above on real Windows. **Requires pushing to GitHub.** |
| Human | Your Windows 11 machine or Windows Sandbox | Smart App Control, Defender/AMSI, Startup Boost, real profile junctions, scan time |

## 7. Changes to the plan

1. **Skip all reparse points** (replaces "skip symlinks"). The deleter never descends into a reparse point.
2. **`\\?\` full paths** for every .NET file call. **Skip and record names** ending in a dot or space, or matching reserved device names.
3. **Startup guards:** LanguageMode is not FullLanguage → exit 3. Elevated → exit 3. Both print a one-line reason.
4. **Recycle flags:** `FOF_ALLOWUNDO|FOF_NOERRORUI|FOF_SILENT|FOF_NOCONFIRMATION|FOF_WANTNUKEWARNING`. The prompt says "Move to Recycle Bin (items too large for it are deleted permanently)".
5. **`--permanent`:** our own bottom-up delete (clear ReadOnly, never follow reparse points). No Remove-Item.
6. **Downloads** resolved through its known-folder GUID. If it isn't under home, it is scanned as a second root for I1 only.
7. **Sizes:** logical, labelled "up to", with notes on pnpm hard links, compression and Dev Drive.
8. **Not cleaned:** pnpm store, `.nuget\packages` (Review at most), anything under `AppData\Local\Packages`.
9. **CI on `windows-latest`** to verify 5.1 for real, if you're OK pushing to GitHub.
10. **UTF-8 console output** set at startup.

## 8. Verified on real Windows (T2 probe, 2026-10-30)

Machine: Windows 11 (build 26300, registry ProductName still says "Windows 10 Home Single Language"), Windows PowerShell 5.1.26100, CLR 4.0.30319, 64-bit, FullLanguage, not elevated, `LongPathsEnabled=1`.

| Question | Answer |
|---|---|
| Do .NET file calls accept `\\?\` paths in 5.1? | **Yes.** `Directory.Exists`, `EnumerateFileSystemInfos`, `File.Delete` and `DirectoryInfo.Delete` all pass with and without the prefix. AppContext: `UseLegacyPathHandling=False`, `BlockLongPaths=False`. The `\\?\` design stands. |
| Paths over 260 characters without `\\?\`? | Work on this machine (355 chars), but `LongPathsEnabled=1` here. Not proven for the default `0`, so keep `\\?\` everywhere. |
| Does `SHFileOperationW` accept `\\?\` paths? | **No.** Plain path: rc 0, source gone. `\\?\` path: rc `0x7C` (ERROR_INVALID_NAME), nothing recycled. Recycle with plain paths only; a recycle that fails is reported as failed. |
| Does Defender/AMSI flag the Add-Type `SHFileOperationW` shim? | **No** (compiled and ran, default Defender). |
| Junction deleted link-only? | **Yes.** `Directory.Delete(link, $false)` removed the link; target and its file survived. `Attributes` = `Directory, ReparsePoint`. |
| ReadOnly delete | Refused with `UnauthorizedAccessException`; succeeds after clearing ReadOnly. |
| Default paths | `AppData\Local\Composer` exists (Roaming `Composer` also exists; that is config, not cache). `AppData\Local\Yarn\Cache`, `npm-cache`, `pip\Cache` exist. `CrashDumps`, `NuGet\v3-cache`, `go-build` absent on this machine (tools not used), so their paths stay **unverified**. Downloads known folder = `C:\Users\<u>\Downloads`, under the profile. |

Still unverified:
- Whether `FOF_WANTNUKEWARNING` shows its dialog when `FOF_SILENT|FOF_NOERRORUI` are set (manual test not done yet).
- Whether `SHFileOperationW` recycles a plain path over 260 characters (with and without `LongPathsEnabled`).
- Whether Smart App Control blocks `junk.ps1` started from `junk.cmd` (the probe ran via `powershell -File`; SAC state of the machine unknown).
- Behaviour with `LongPathsEnabled=0`.
- `CrashDumps`, NuGet and go-build default paths.
- Scan time of a PowerShell loop on a large profile. `ponytail:` move the hot loop into the Add-Type C# if it's over about 5 min.

## Sources

PowerShell and policy
- [about_Language_Modes](https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_language_modes) · [How App Control works with PowerShell](https://learn.microsoft.com/powershell/scripting/security/app-control/how-app-control-works) · [PowerShell team: CLM and DeviceGuard (2017)](https://devblogs.microsoft.com/powershell/?p=13707) · [App Control for Windows](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol)
- [about_Signing](https://learn.microsoft.com/en-ca/powershell/module/microsoft.powershell.core/about/about_signing?view=powershell-7.4) · [Bypassing RemoteSigned / MOTW](https://ferreirasc.github.io/bypassing-remotesigned) · [Execution policy GPO override](https://theitbros.com/powershell-running-scripts-is-disabled-on-this-system/)
- [Smart App Control: what it blocks](https://geekrewind.com/what-windows-11-smart-app-control-actually-blocks-and-how-to-disable-it/) · [.exe/.cmd/.ps1 blocks on Win 11](https://windows.gadgethacks.com/how-to/windows-11-cant-run-exe-files-fix-exe-cmd-and-ps1-blocks/) · [MS Q&A: signed app blocked by SAC](https://learn.microsoft.com/en-us/answers/questions/5791210/application-signed-and-blocked-by-smart-app-contro)
- [Why is Get-ChildItem so slow](https://devblogs.microsoft.com/powershell/why-is-get-childitem-so-slow/) · [EnumerateFiles vs dir benchmark](https://kiwix.lema.org/stackoverflow.com_en_all_2023-11/a/54222055) · [Remove-Item docs](https://learn.microsoft.com/powershell/module/microsoft.powershell.management/remove-item) · [PowerShell #16664](https://github.com/PowerShell/PowerShell/issues/16664)
- [about_Character_Encoding (5.1)](https://learn.microsoft.com/fr-fr/powershell/module/microsoft.powershell.core/about/about_character_encoding?view=powershell-5.1) · [5.1 redirect encoding traps](https://braindetox.kr/en/posts/powershell_5_1_redirect_encoding_traps.html)
- [Pester installation](https://pester.dev/docs/v5/introduction/installation) · [Add-Type on 5.1 (no CompilerOptions)](https://github.com/getsentry/sentry-powershell/pull/129) · [PowerShell class/Add-Type compile cost](https://deadlydog.github.io/PowerShell-class-definition-pros-cons-and-performance-comparison/) · [PowerShell #21546 (CFA)](https://github.com/PowerShell/PowerShell/issues/21546)
- [AMSI and DllImport](https://s3cur3th1ssh1t.github.io/Powershell-and-the-.NET-AMSI-Interface)

Filesystem
- [Maximum path length limitation](https://learn.microsoft.com/zh-cn/windows/win32/fileio/maximum-file-path-limitation) · [.NET long path support](https://github.com/microsoft/dotnet/blob/main/Documentation/compatibility/long-path-support.md) · [MS Q&A: long paths .NET 4.6.2](https://learn.microsoft.com/en-us/answers/questions/240603/c-app-long-path-support-on-windows-10-post-1607-ne) · [Long paths in PowerShell](https://wil.dev/posts/long-path-powershell/)
- [PathCchCanonicalizeEx (trailing dots/spaces)](https://learn.microsoft.com/windows/win32/api/pathcch/nf-pathcch-pathcchcanonicalizeex) · [CPython #85681](https://github.com/python/cpython/issues/85681)
- [Profile junction loop (BleachBit)](https://www.bleachbit.org/node/3995) · [Profile junction permissions](https://ohmancorp.com/RefWin-Win2008R2-AltProfilesFixJuctions.asp) · [Hardlinks, symlinks, junctions](https://hy2k.dev/en/blog/2025/11-23-windows-hardlink-symlink-junction/)
- [Handling placeholders (cloud files)](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/placeholders_guidance) · [Cloud files enumerations](https://learn.microsoft.com/en-us/windows/win32/cfapi/cloud-files-enumerations)
- [GetCompressedFileSizeW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getcompressedfilesizew) · [Sparse file size](https://learn.microsoft.com/cs-cz/windows/win32/FileIO/obtaining-the-size-of-a-sparse-file) · [Block cloning](https://learn.microsoft.com/windows/win32/fileio/block-cloning) · [pnpm FAQ](https://pnpm.io/faq)
- [Rename is multi-step (Old New Thing)](https://devblogs.microsoft.com/oldnewthing/20211022-00/?p=105822) · [OSR: rename dir with open descendant](https://community.osr.com/t/basic-question-on-rename/28355) · [Git read-only files on Windows](https://scriptagc.wasmer.app/https_superuser_com/questions/1321648/why-does-git-for-windows-create-repositories-that-i-cant-delete-from-a-command)

Recycle Bin
- [SHFileOperationW](https://learn.microsoft.com/windows/win32/api/shellapi/nf-shellapi-shfileoperationw) · [IFileOperation::SetOperationFlags](https://msdn.microsoft.com/en-us/library/bb775799(v=vs.85)) · [Safely delete folder to Recycle Bin (SO)](https://kiwix.lema.org/stackoverflow.com_en_all_2023-11/questions/23720519/how-to-safely-delete-folder-into-recycle-bin) · [AutoHotkey FileRecycle](https://www.autohotkey.com/docs/v1/lib/FileRecycle.htm)
- [Default Recycle Bin size (Old New Thing)](https://devblogs.microsoft.com/oldnewthing/20140701-00/?p=603) · [Recycle Bin max size, Win 11](https://www.elevenforum.com/t/change-maximum-size-for-recycle-bin-in-windows-11.5109/) · [Files too large for Recycle Bin](https://idiskhome.com/resource/recover/recover-files-too-large-for-recycle-bin.shtml)
- [FileSystem.DeleteDirectory](https://learn.microsoft.com/th-th/dotnet/api/microsoft.visualbasic.fileio.filesystem.deletedirectory?view=net-8.0)

Defender, processes, locations
- [Enable controlled folder access](https://learn.microsoft.com/en-nz/defender-endpoint/enable-controlled-folders) · [CFA and scripting engines](https://www.petervanderwoude.nl/post/protecting-important-folders-with-controlled-folder-access)
- [Detect elevated process (PowerShell Magazine)](https://powershellmagazine.com/2013/03/29/pstip-detecting-if-a-certain-process-is-elevated/) · [Edge StartupBoostEnabled](https://learn.microsoft.com/DeployEdge/microsoft-edge-browser-policies/startupboostenabled) · [WebView2 hosts](https://oofhours.com/2022/01/30/the-overhead-of-widgets-and-teams-in-windows-11/)
- [npm cache docs fix](https://github.com/npm/cli/commit/97c32ed24d8fa2edcdbb9448839a1f1c9d8fb86f) · [Chrome cache folders](https://chrome-tips.pages.dev/articles/chrome-cache-folder-size-and-location/) · [Edge Code Cache](https://techcommunity.microsoft.com/discussions/windows10space/how-can-i-clear-browser-cache-from-chrome/4484947)
- [WER registry and folders](https://github.com/libyal/winreg-kb/blob/main/docs/sources/system-keys/Windows-error-reporting.md) · [WER for developers](https://learn.microsoft.com/fr-fr/archive/blogs/oanapl/windows-error-reporting-wer-for-developers) · [WER files (forensics)](https://psmths.gitbook.io/windows-forensics/artifacts-by-type/filesystem-artifacts/wer-files)
- [Known folder paths in .NET](https://static.codeproject.com/Articles/878605/Getting-All-Special-Folders-in-NET) · [Redirect Downloads (MS Q&A)](https://learn.microsoft.com/en-us/answers/questions/505427/how-do-i-redirect-a-folder-programmatically-specia)
- [Storage Sense temp files](https://geekrewind.com/how-to-clear-temporary-files-using-storage-sense-in-windows-11/) · [Disk Cleanup deprecated](https://en.wikipedia.org/wiki/Disk_Cleanup)
