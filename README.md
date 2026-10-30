# JunkFinder for Windows

**Find the junk filling up your Windows PC. Clean it safely with one command.**

<!-- TODO(T8): real trimmed junk.cmd scan + clean run goes here -->

## What it cleans

| Junk | Example |
|---|---|
| Browser caches | Chrome, Edge, Brave and Firefox caches |
| Electron app caches | `Cache`, `Code Cache` and `GPUCache` of Slack, Discord, VS Code and similar |
| Old crash reports | Windows Error Reporting reports and crash dumps older than 7 days |
| Old temp files | Items in your `Temp` folder older than 7 days |
| Developer caches | npm, pip, Yarn, Composer, NuGet download and Go build caches, Cargo registry cache |
| Old `node_modules` | Projects you haven't installed in for more than 30 days, with a lock file |
| Old Composer `vendor` | PHP projects you haven't installed in for more than 30 days, with a lock file |
| Old installers | `.msi`, `.msix` and `.appx` files in Downloads, added more than 30 days ago |

Caches and dependency folders are rebuilt or re-downloaded on demand. Old temp files, crash reports and installers are simply gone.

Some things are only listed as **Review**, never cleaned: Rust `target` folders, `.exe` and `.iso` files in Downloads added more than 30 days ago, and files of 500 MB or more not modified in over 180 days.

## Safe by default

- **Look first.** Plain `junk.cmd` only reads; it shows what it finds and deletes nothing. Only `junk.cmd clean` removes, after you say yes.
- **Recycle Bin by default.** Items go to the Recycle Bin so you can restore them. But the Recycle Bin is a request: items too big for it, or a drive set to "Don't move files to the Recycle Bin", are deleted permanently, and the summary may still say "Moved". With `--yes` Windows does not ask first. `--permanent` skips the Recycle Bin on purpose.
- **Hands off your stuff.** Documents, Desktop, Pictures, Music, Videos, OneDrive, SSH/GPG/cloud credentials and app packages are never scanned. Only Junk is cleaned, never Review.
- **Apps stay happy.** Browser and Electron app caches are skipped while that app runs (matched by process name).

## Try it

```bat
git clone https://github.com/digitaldreams/windows-junk-finder.git
cd windows-junk-finder
junk.cmd
junk.cmd clean temp caches
```

The first `junk.cmd` shows your junk. The second line cleans temp files and caches.

Pick what to clean: `caches`, `logs`, `temp`, `dev`, `installers`, `node_modules`, `vendor`. Add `--yes` to skip the question, `--permanent` to skip the Recycle Bin.

## Requirements

- Windows 11 with the built-in Windows PowerShell 5.1 (not PowerShell 7).
- 64-bit.
- A normal user. It refuses to run as administrator.

If Windows blocks the script, or Edge's cache is skipped, see [Blocked by Windows](docs/how-it-works.md#if-windows-blocks-it) and [Edge Startup Boost](docs/how-it-works.md#edge-startup-boost).

**Want the details?** See [how it works](docs/how-it-works.md).
