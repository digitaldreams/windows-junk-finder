Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

function New-JunkMatch {
    param([string]$Category, [string]$Tier, [string]$RuleId, [string]$Reason)
    [pscustomobject]@{ Category = $Category; Tier = $Tier; RuleId = $RuleId; Reason = $Reason }
}

# True when the first $Prefix.Count path parts equal $Prefix (case-insensitive).
function Test-PathPrefix {
    param([string[]]$Parts, [string[]]$Prefix)
    if ($Parts.Count -lt $Prefix.Count) { return $false }
    for ($i = 0; $i -lt $Prefix.Count; $i++) {
        if ($Parts[$i] -ne $Prefix[$i]) { return $false }
    }
    $true
}

# ponytail: first-match chain (deny, D, C, I, B) like Rules.swift; fine for ~12 rules, switch to a table past ~20.
function Get-JunkMatch {
    param($Item, [datetime]$Now)
    $parts = @($Item.Path.ToLowerInvariant().Split('\'))
    if ($parts -contains '') { return $null }
    $n = $parts.Count
    $name = $parts[$n - 1]
    $isDir = $Item.Kind -eq 'dir'
    $siblings = @($Item.Siblings)
    $ageDays = { param($t) ($Now - $t).TotalDays }

    # Deny: stores shared through hard links or read-only package trees
    if ((Test-PathPrefix $parts @('appdata', 'local', 'pnpm')) -or
        (Test-PathPrefix $parts @('.pnpm-store')) -or
        (Test-PathPrefix $parts @('.nuget', 'packages'))) { return $null }

    if ($isDir) {
        # D3
        $d3 = @('appdata\local\npm-cache', 'appdata\local\pip\cache', 'appdata\local\yarn\cache', 'appdata\local\composer',
            'appdata\local\nuget\v3-cache', 'appdata\local\go-build', '.cargo\registry\cache')
        if ($d3 -contains ($parts -join '\')) {
            return New-JunkMatch 'Dev junk' 'junk' 'D3' 'package manager download cache; re-downloaded on demand'
        }
        # D4
        if ($name -eq 'target' -and $siblings -contains 'Cargo.toml') {
            return New-JunkMatch 'Dev junk' 'review' 'D4' 'Rust build output next to Cargo.toml; rebuilt by cargo'
        }
        # D5 / D6: per-user apps (AppData) and dot folders ship their own package.json/composer.json
        $hidden = $parts[0].StartsWith('.') -or $parts[0] -eq 'appdata'
        $stale = (& $ageDays $Item.Modified) -gt 30
        if (-not $hidden -and $name -eq 'node_modules' -and $siblings -contains 'package.json') {
            $locks = @('package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'bun.lockb', 'bun.lock')
            $hasLock = @($locks | Where-Object { $siblings -contains $_ }).Count -gt 0
            if ($stale -and $hasLock) {
                return New-JunkMatch 'Dev junk' 'junk' 'D5' 'npm packages, unchanged for over 30 days; npm install restores them'
            }
            return New-JunkMatch 'Dev junk' 'review' 'D5' 'project build/dependency folder; restored by package manager'
        }
        if (-not $hidden -and $name -eq 'vendor' -and $siblings -contains 'composer.json') {
            if ($stale -and $siblings -contains 'composer.lock') {
                return New-JunkMatch 'Dev junk' 'junk' 'D6' 'Composer packages, unchanged for over 30 days; composer install restores them'
            }
            return New-JunkMatch 'Dev junk' 'review' 'D6' 'Composer packages; composer install restores them'
        }
        # C1: <vendor>\<product>\User Data\<Profile>\<cache> and Firefox cache2
        if ($n -ge 6 -and $parts[0] -eq 'appdata' -and $parts[1] -eq 'local') {
            $browser = @('google\chrome', 'microsoft\edge', 'bravesoftware\brave-browser') -contains ($parts[2] + '\' + $parts[3])
            if ($browser -and $parts[4] -eq 'user data') {
                $caches = @('cache', 'code cache', 'gpucache', 'media cache')
                if (($n -eq 7 -and $caches -contains $name) -or ($n -eq 6 -and $name -eq 'shadercache')) {
                    return New-JunkMatch 'Caches & logs' 'junk' 'C1' 'browser cache; close the browser before deleting'
                }
            }
            if ($n -eq 7 -and $parts[2] -eq 'mozilla' -and $parts[3] -eq 'firefox' -and $parts[4] -eq 'profiles' -and $name -eq 'cache2') {
                return New-JunkMatch 'Caches & logs' 'junk' 'C1' 'browser cache; close the browser before deleting'
            }
        }
        # C1e: Chromium/Electron signature is a GPUCache next to the cache dirs
        if ($n -eq 4 -and $parts[0] -eq 'appdata' -and $parts[1] -eq 'roaming' -and
            @('cache', 'code cache', 'gpucache') -contains $name -and $siblings -contains 'GPUCache') {
            return New-JunkMatch 'Caches & logs' 'junk' 'C1e' 'app cache; quit the app before deleting'
        }
    }

    # C2, C3 (dirs or files, by age)
    $old7 = (& $ageDays $Item.Modified) -gt 7
    if ($old7 -and $n -eq 7 -and (Test-PathPrefix $parts @('appdata', 'local', 'microsoft', 'windows', 'wer')) -and
        @('reportarchive', 'reportqueue') -contains $parts[5]) {
        return New-JunkMatch 'Caches & logs' 'junk' 'C2' 'crash report older than 7 days'
    }
    if ($old7 -and -not $isDir -and $n -eq 4 -and (Test-PathPrefix $parts @('appdata', 'local', 'crashdumps'))) {
        return New-JunkMatch 'Caches & logs' 'junk' 'C2' 'crash report older than 7 days'
    }
    if ($old7 -and $n -eq 4 -and (Test-PathPrefix $parts @('appdata', 'local', 'temp'))) {
        return New-JunkMatch 'Caches & logs' 'junk' 'C3' 'temp file older than 7 days'
    }

    if (-not $isDir) {
        # I1: Windows has no "date added"; the newer of created/modified resists copied-in old timestamps
        # ponytail: "depth <= 2" read as at most 2 levels below Downloads (Downloads\sub\x.msi), like the Mac rule.
        if ($parts[0] -eq 'downloads' -and $n -le 3) {
            # not GetExtension: it throws on .NET Framework for names with "<>| or control chars
            $dot = $name.LastIndexOf('.')
            $ext = ''
            if ($dot -gt 0) { $ext = $name.Substring($dot + 1) }
            $added = $Item.Modified
            if ($Item.Created -gt $added) { $added = $Item.Created }
            if ((& $ageDays $added) -gt 30) {
                if (@('msi', 'msix', 'msixbundle', 'appx', 'appxbundle') -contains $ext) {
                    return New-JunkMatch 'Old installers' 'junk' 'I1' 'installer added over 30 days ago'
                }
                if (@('exe', 'iso') -contains $ext) {
                    return New-JunkMatch 'Old installers' 'review' 'I1' "installer or disk image; make sure it isn't your only copy"
                }
            }
        }
        # B1
        if ($Item.Size -ge 500000000 -and (& $ageDays $Item.Modified) -gt 180) {
            return New-JunkMatch 'Big files' 'review' 'B1' 'large file (500 MB or more), not modified in over 180 days'
        }
    }
    $null
}

# ---- T4 Scanner ----

$script:IsWindows5 = $env:OS -eq 'Windows_NT'

# \\?\ prefix for every .NET file call on Windows (research section 8); no-op elsewhere.
function Get-LongPath {
    param([string]$Path)
    if (-not $script:IsWindows5 -or $Path.StartsWith('\\?\')) { return $Path }
    if ($Path.StartsWith('\\')) { return '\\?\UNC\' + $Path.Substring(2) }
    '\\?\' + $Path
}

# Downloads known folder from the registry; $null off Windows or when unset.
function Get-DownloadsFolder {
    if (-not $script:IsWindows5) { return $null }
    $key = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders')
    if ($null -eq $key) { return $null }
    $v = $key.GetValue('{374DE290-123F-4565-9164-39C4925E467B}', $null, 'DoNotExpandEnvironmentNames')
    if ($v) { return [Environment]::ExpandEnvironmentVariables([string]$v) }
    $null
}

# Local fixed drive only: network and removable drives have no Recycle Bin, so a "recycle" there deletes permanently.
function Test-FixedDrive {
    param([string]$Path)
    if ($Path.StartsWith('\\')) { return $false }
    if (-not $script:IsWindows5) { return $true }
    try { (New-Object IO.DriveInfo ([IO.Path]::GetPathRoot($Path))).DriveType -eq 'Fixed' } catch { $false }
}

# Exception (or anything it wraps) -> skip kind.
function Get-ScanErrorKind {
    param($Exception)
    for ($e = $Exception; $null -ne $e; $e = $e.InnerException) {
        if ($e -is [UnauthorizedAccessException]) { return 'access denied' }
        if ($e -is [IO.PathTooLongException]) { return 'path too long' }
    }
    'unreadable'
}

# '' = fine, else why the entry is neither descended nor counted. Cloud first: placeholders are usually reparse points too.
function Get-EntryVerdict {
    param([string]$Name, [int]$Attr)
    if (($Attr -band 0x441000) -ne 0) { return 'cloud-only' }   # OFFLINE | RECALL_ON_OPEN | RECALL_ON_DATA_ACCESS
    if (($Attr -band 0x400) -ne 0) { return 'reparse' }
    $last = $Name[$Name.Length - 1]
    if ($last -eq '.' -or $last -eq ' ') { return 'unaddressable name' }
    $dot = $Name.IndexOf('.')
    $base = $Name
    if ($dot -ge 0) { $base = $Name.Substring(0, $dot) }
    if ($base.TrimEnd(' ') -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$') { return 'unaddressable name' }
    ''
}

function Add-ScanSkip {
    param($Ctx, [string]$Path, [string]$Kind)
    if ($Ctx.Seen.ContainsKey($Path)) { return }
    $Ctx.Seen[$Path] = $true
    $Ctx.Skipped.Add([pscustomobject]@{ Path = $Path; Kind = $Kind })
}

# Lists one folder (own try/catch). Returns $null after recording the failure.
function Get-DirEntries {
    param($Ctx, [string]$Full, [string]$Rel)
    $list = New-Object 'System.Collections.Generic.List[IO.FileSystemInfo]'
    try {
        $di = New-Object IO.DirectoryInfo (Get-LongPath $Full)
        foreach ($e in $di.EnumerateFileSystemInfos()) { $list.Add($e) }
    } catch {
        Add-ScanSkip $Ctx $Rel (Get-ScanErrorKind $_.Exception)
        return $null
    }
    , $list
}

# Size and newest file time of a matched dir, in one walk. $null when its own listing fails.
function Measure-JunkDir {
    param($Ctx, [string]$Full, [string]$Rel)
    $sep = [IO.Path]::DirectorySeparatorChar
    $size = [long]0
    $newest = [DateTime]::MinValue
    $stack = New-Object 'System.Collections.Generic.Stack[string[]]'
    $stack.Push([string[]]@($Full, $Rel))
    $first = $true
    $incomplete = $false
    while ($stack.Count -gt 0) {
        $cur = $stack.Pop()
        $entries = Get-DirEntries $Ctx $cur[0] $cur[1]
        if ($null -eq $entries) {
            if ($first) { return $null }
            $incomplete = $true
            continue
        }
        $first = $false
        foreach ($e in $entries) {
            $rel = $cur[1] + '\' + $e.Name
            try {
                $attr = [int]$e.Attributes
                $v = Get-EntryVerdict $e.Name $attr
                # ponytail: any inner skip (even a plain link, e.g. pnpm junctions) forces Review; age/size are then incomplete.
                if ($v -eq 'reparse') { $incomplete = $true; continue }
                if ($v -ne '') { $incomplete = $true; Add-ScanSkip $Ctx $rel $v; continue }
                if (($attr -band 0x10) -ne 0) {
                    $stack.Push([string[]]@(($cur[0] + $sep + $e.Name), $rel))
                } else {
                    $size += $e.Length
                    $t = $e.LastWriteTimeUtc
                    if ($t -gt $newest) { $newest = $t }
                }
            } catch {
                $incomplete = $true
                Add-ScanSkip $Ctx $rel (Get-ScanErrorKind $_.Exception)
            }
        }
    }
    [pscustomobject]@{ Size = $size; Newest = $newest; Incomplete = $incomplete }
}

function Add-Finding {
    param($Ctx, $Item, $Match, [string]$Full, [string]$OnlyRule)
    if ($null -eq $Match) { return }
    if ($OnlyRule -and $Match.RuleId -ne $OnlyRule) { return }
    $Ctx.Findings.Add([pscustomobject]@{
        Path = $Item.Path; FullPath = $Full; Kind = $Item.Kind; Size = $Item.Size
        Modified = $Item.Modified; Created = $Item.Created
        Category = $Match.Category; Tier = $Match.Tier; RuleId = $Match.RuleId; Reason = $Match.Reason
    })
}

# ponytail: PowerShell hot loop (research section 8: unmeasured on a big profile). Ceiling ~1M entries in a few minutes;
# past that move the loop into Add-Type C#. Get-JunkMatch runs for every file; add a cheap prefilter if that dominates.
function Invoke-JunkWalk {
    param($Ctx, [string]$Root, [string]$RelPrefix, [bool]$IsHome, [string]$OnlyRule, [datetime]$Now)
    $sep = [IO.Path]::DirectorySeparatorChar
    $min = [DateTime]::MinValue
    $stack = New-Object 'System.Collections.Generic.Stack[string[]]'
    $stack.Push([string[]]@($Root, $RelPrefix))
    while ($stack.Count -gt 0) {
        $cur = $stack.Pop()
        $entries = Get-DirEntries $Ctx $cur[0] $cur[1]
        if ($null -eq $entries) { continue }
        $names = New-Object 'System.Collections.Generic.List[string]'
        foreach ($e in $entries) { $names.Add($e.Name) }
        foreach ($e in $entries) {
            $name = $e.Name
            if ($cur[1] -eq '') { $rel = $name } else { $rel = $cur[1] + '\' + $name }
            $full = $cur[0] + $sep + $name
            try {
                $attr = [int]$e.Attributes
                $v = Get-EntryVerdict $name $attr
                if ($v -eq 'reparse') { continue }
                if ($v -ne '') { Add-ScanSkip $Ctx $rel $v; continue }
                if (($attr -band 0x10) -ne 0) {
                    if ($IsHome -and $script:SkipDirs.Contains($rel)) { continue }
                    if ($IsHome -and $cur[1] -eq '' -and $name.StartsWith('OneDrive', [StringComparison]::OrdinalIgnoreCase)) { continue }
                    # I1 reaches Downloads\sub\x only: don't list dirs below depth 2.
                    if ($OnlyRule) {
                        if (($rel.Split('\')).Count -le 2) { $stack.Push([string[]]@($full, $rel)) }
                        continue
                    }
                    # Candidate test with an "infinitely old" dir; real age needs the walk inside.
                    $probe = [pscustomobject]@{ Path = $rel; Kind = 'dir'; Siblings = $names; Size = 0; Modified = $min; Created = $min }
                    if ($null -eq (Get-JunkMatch -Item $probe -Now $Now)) {
                        $stack.Push([string[]]@($full, $rel))
                        continue
                    }
                    $m = Measure-JunkDir $Ctx $full $rel
                    if ($null -eq $m -or $m.Size -eq 0) { continue }
                    $mod = $m.Newest
                    $item = [pscustomobject]@{ Path = $rel; Kind = 'dir'; Siblings = $names; Size = $m.Size; Modified = $mod; Created = $e.CreationTimeUtc }
                    # ponytail: a candidate whose real match fails (e.g. young temp dir) is not descended into.
                    $match = Get-JunkMatch -Item $item -Now $Now
                    if ($null -ne $match -and $m.Incomplete) {
                        $match = New-JunkMatch $match.Category 'review' $match.RuleId ($match.Reason + '; some contents could not be read')
                    }
                    Add-Finding $Ctx $item $match $full $OnlyRule
                } else {
                    $item = [pscustomobject]@{ Path = $rel; Kind = 'file'; Siblings = $names; Size = [long]$e.Length; Modified = $e.LastWriteTimeUtc; Created = $e.CreationTimeUtc }
                    Add-Finding $Ctx $item (Get-JunkMatch -Item $item -Now $Now) $full $OnlyRule
                }
            } catch {
                Add-ScanSkip $Ctx $rel (Get-ScanErrorKind $_.Exception)
            }
        }
    }
}

# Dirs never entered, matched on the path relative to home (case-insensitive). OneDrive* is handled in the walk.
$script:SkipDirs = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
foreach ($d in @('Documents', 'Desktop', 'Pictures', 'Music', 'Videos', 'Favorites', '.ssh', '.gnupg', '.aws', '.azure', '.kube',
        '.config', '.local', '.cache', '.rustup', '.cargo\bin', '.nuget\packages', '.pnpm-store', 'scoop',
        'AppData\Local\Packages', 'AppData\Local\Microsoft\WindowsApps', 'AppData\Local\Microsoft\Outlook',
        'AppData\Local\Microsoft\Credentials', 'AppData\Local\Programs', 'AppData\Local\pnpm', 'AppData\Roaming\Microsoft')) {
    [void]$script:SkipDirs.Add($d)
}

function Invoke-JunkScan {
    param([string]$Root, [datetime]$Now, [string]$ExtraRoot)
    $ctx = @{
        Findings = New-Object 'System.Collections.Generic.List[object]'
        Skipped  = New-Object 'System.Collections.Generic.List[object]'
        Seen     = @{}
    }
    $sep = [IO.Path]::DirectorySeparatorChar
    $home_ = $Root.TrimEnd('\', '/')
    Invoke-JunkWalk $ctx $home_ '' $true '' $Now
    if (-not $PSBoundParameters.ContainsKey('ExtraRoot')) { $ExtraRoot = Get-DownloadsFolder }
    if ($ExtraRoot) {
        $extra = $ExtraRoot.TrimEnd('\', '/')
        $inside = $extra.StartsWith($home_ + $sep, [StringComparison]::OrdinalIgnoreCase) -or $extra -eq $home_
        if ($inside) { }
        elseif (-not (Test-FixedDrive $extra)) { Add-ScanSkip $ctx 'Downloads' 'network or removable drive' }
        else { Invoke-JunkWalk $ctx $extra 'Downloads' $false 'I1' $Now }
    }
    @{ Findings = $ctx.Findings.ToArray(); Skipped = $ctx.Skipped.ToArray() }
}

# ---- T5 Report, CLI, guards ----

# Printed paths come from the filesystem: no terminal escapes, newlines or bidi overrides.
function ConvertTo-SafeText {
    param([string]$Text)
    [regex]::Replace($Text, '[\x00-\x1F\x7F\u0080-\u009F\u202A-\u202E\u2066-\u2069]', '?')
}

# 1000-based like Finder: "999 KB", "1.0 MB", "340 MB". A value that rounds up to 1000 moves to the next unit.
function Format-JunkSize {
    param([long]$Bytes)
    if ($Bytes -lt 1000) { return "$Bytes B" }
    $units = @('KB', 'MB', 'GB', 'TB')
    $away = [MidpointRounding]::AwayFromZero
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $v = $Bytes / 1000.0
    $i = 0
    while ($true) {
        $r1 = [math]::Round($v * 10, $away) / 10
        $whole = $i -eq 0 -or $r1 -ge 100
        if ($whole) { $r = [math]::Round($v, $away) } else { $r = $r1 }
        if ($r -ge 1000 -and $i -lt $units.Count - 1) { $v = $v / 1000; $i++; continue }
        if ($whole) { return $r.ToString('F0', $inv) + ' ' + $units[$i] }
        return $r.ToString('F1', $inv) + ' ' + $units[$i]
    }
}

function Format-JunkReport {
    param($Result, [datetime]$Now)
    $sections = @(@('Caches & logs', 'Caches & logs'), @('Dev junk', 'Dev junk'), @('Old installers', 'Old installers'), @('Big files', 'Big files'))
    $findings = @($Result.Findings)
    $sb = New-Object Text.StringBuilder
    foreach ($sec in $sections) {
        $rows = @($findings | Where-Object { $_.Category -eq $sec[0] } | Sort-Object -Property Size -Descending)
        if ($rows.Count -eq 0) { continue }
        [void]$sb.Append($sec[1]).Append("`n")
        foreach ($f in $rows) {
            $label = 'modified'
            $date = $f.Modified
            if ($f.RuleId -eq 'I1') { $label = 'added'; if ($f.Created -gt $date) { $date = $f.Created } }
            $days = [math]::Max(0, [int][math]::Truncate(($Now - $date).TotalDays))
            $tier = 'review'
            if ($f.Tier -eq 'junk') { $tier = 'junk' }
            [void]$sb.Append('  ').Append((Format-JunkSize $f.Size).PadLeft(8)).Append('  ').Append($tier.PadRight(6)).Append('  ')
            [void]$sb.Append('~\').Append((ConvertTo-SafeText $f.Path)).Append("  ($label $days d ago)  ")
            [void]$sb.Append((ConvertTo-SafeText $f.RuleId)).Append(': ').Append((ConvertTo-SafeText $f.Reason)).Append("`n")
        }
        [void]$sb.Append("`n")
    }
    if ($findings.Count -eq 0) { [void]$sb.Append("No junk found.`n`n") }
    $sum = { param($t) $n = [long]0; foreach ($f in $findings) { if ($f.Tier -eq $t) { $n += $f.Size } }; $n }
    [void]$sb.Append('Junk (reclaimable): up to ').Append((Format-JunkSize (& $sum 'junk'))).Append("`n")
    [void]$sb.Append('Review (check before deleting): up to ').Append((Format-JunkSize (& $sum 'review'))).Append("`n`n")

    # Known kinds in a fixed order, any other kind after them.
    $skipped = @($Result.Skipped)
    $order = @('access denied', 'path too long', 'unreadable', 'cloud-only', 'unaddressable name', 'network or removable drive')
    $present = @($skipped | ForEach-Object { $_.Kind })
    $kinds = @($order | Where-Object { $present -contains $_ }) + @($present | Where-Object { $order -notcontains $_ } | Select-Object -Unique)
    $parts = foreach ($k in $kinds) {
        $paths = @($skipped | Where-Object { $_.Kind -eq $k } | ForEach-Object { $_.Path })
        $named = (@($paths | Select-Object -First 3 | ForEach-Object { '~\' + (ConvertTo-SafeText $_) })) -join ', '
        if ($paths.Count -gt 3) { $named += ', ...' }
        "$($paths.Count) $(ConvertTo-SafeText $k) ($named)"
    }
    if ($skipped.Count -eq 0) { [void]$sb.Append("Skipped: none`n`n") }
    else { [void]$sb.Append('Skipped (not counted, sizes incomplete): ').Append(@($parts) -join '; ').Append("`n`n") }
    [void]$sb.Append("Notes`n")
    [void]$sb.Append("- Sizes are logical (file lengths); NTFS compression, pnpm hard links and Dev Drive block clones can make totals overstate.`n")
    [void]$sb.Append("- Skipped and built-in excluded areas are not scanned, so totals are a lower bound.`n")
    [void]$sb.Append("- Not scanned by design: OneDrive, Documents, Desktop, Pictures, Music, Videos, app packages, credentials.`n")
    $sb.ToString()
}

# $null when fine, else the one-line reason to stop (exit 3).
function Get-StartupBlock {
    param([string]$LanguageMode, [bool]$Elevated)
    if ($LanguageMode -ne 'FullLanguage') {
        return 'Constrained Language Mode (App Control/AppLocker) blocks JunkFinder; run it on an unmanaged machine.'
    }
    if ($Elevated) { return 'Run JunkFinder as a normal user, not as administrator.' }
    $null
}

function Test-Elevated {
    if (-not $script:IsWindows5) { return $false }
    (New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ---- T6 junk clean ----
# Only this section may recycle or delete: Junk tier only, after confirmation and per-item re-checks.

$script:CleanUsage = 'Usage: junk clean <caches|logs|temp|dev|installers|node_modules|vendor>... [--yes] [--permanent]'
$script:SectionRules = @{
    caches = @('C1', 'C1e'); logs = @('C2'); temp = @('C3'); dev = @('D3')
    installers = @('I1'); node_modules = @('D5'); vendor = @('D6')
}

# $Arguments are the words after `clean`.
function ConvertFrom-CleanArgs {
    param([string[]]$Arguments)
    $o = @{ Ok = $false; Message = ''; Sections = @(); Yes = $false; Permanent = $false }
    foreach ($a in @($Arguments)) {
        $k = $a.ToLowerInvariant()
        if ($k -eq '--yes') { $o.Yes = $true }
        elseif ($k -eq '--permanent') { $o.Permanent = $true }
        elseif ($k -eq 'big') { $o.Message = 'Big files are Review only; delete them by hand'; return $o }
        elseif ($script:SectionRules.ContainsKey($k)) { if ($o.Sections -notcontains $k) { $o.Sections += $k } }
        else { $o.Message = "Unknown argument '" + (ConvertTo-SafeText $a) + "'.`n" + $script:CleanUsage; return $o }
    }
    if ($o.Sections.Count -eq 0) { $o.Message = $script:CleanUsage; return $o }
    $o.Ok = $true
    $o
}

# Returns remove (findings) and skipped (finding + reason).
function Get-CleanPlan {
    param($Result, [string[]]$Sections, [string[]]$Running)
    $rules = @($Sections | ForEach-Object { $script:SectionRules[$_] })
    $browsers = @{ 'google\chrome' = 'chrome'; 'microsoft\edge' = 'msedge'; 'bravesoftware\brave-browser' = 'brave'; 'mozilla\firefox' = 'firefox' }
    $remove = New-Object 'System.Collections.Generic.List[object]'
    $skipped = New-Object 'System.Collections.Generic.List[object]'
    foreach ($f in @($Result.Findings)) {
        if ($f.Tier -ne 'junk' -or $rules -notcontains $f.RuleId) { continue }
        $parts = @($f.Path.Split('\'))
        $why = ''
        # ponytail: name match only. Map Teams/Discord process names if real runs show misses.
        if ($f.RuleId -eq 'C1' -and $parts.Count -ge 4) {
            $proc = $browsers[($parts[2] + '\' + $parts[3]).ToLowerInvariant()]
            if ($proc -and $Running -contains $proc) {
                $why = 'app running'
                if ($proc -eq 'msedge') { $why += ' (Edge Startup Boost keeps it running; turn it off in edge://settings/system)' }
            }
        } elseif ($f.RuleId -eq 'C1e' -and $parts.Count -ge 3 -and $Running -contains $parts[2]) {
            $why = 'app running'
        }
        if ($why) { $skipped.Add([pscustomobject]@{ finding = $f; reason = $why }) } else { $remove.Add($f) }
    }
    @{ remove = $remove.ToArray(); skipped = $skipped.ToArray() }
}

function Test-UnderRoot {
    param([string]$Path, [string]$Root)
    $Path.StartsWith($Root + '\', [StringComparison]::OrdinalIgnoreCase) -or $Path.StartsWith($Root + '/', [StringComparison]::OrdinalIgnoreCase)
}

# The root a finding must stay under (home, or the Downloads root on a fixed drive); $null when neither.
function Get-FindingRoot {
    param($Finding, [string]$HomeRoot, [string]$ExtraRoot)
    $h = $HomeRoot.TrimEnd('\', '/')
    if (Test-UnderRoot $Finding.FullPath $h) { return $h }
    if ($ExtraRoot) {
        $x = $ExtraRoot.TrimEnd('\', '/')
        if ((Test-UnderRoot $Finding.FullPath $x) -and (Test-FixedDrive $x)) { return $x }
    }
    $null
}

# $null when the item may still be removed, else why not. Metadata only; every component gets lstat-style attributes.
function Test-CleanTarget {
    param($Finding, [string]$Root)
    $root_ = $Root.TrimEnd('\', '/')
    if (-not (Test-UnderRoot $Finding.FullPath $root_)) { return 'path is not under the root' }
    $parts = @($Finding.FullPath.Substring($root_.Length + 1).Split([char[]]@('\', '/')))
    foreach ($p in $parts) { if ($p -eq '' -or $p -eq '.' -or $p -eq '..') { return 'path is not under the root' } }
    $sep = [IO.Path]::DirectorySeparatorChar
    $cur = $root_
    for ($i = 0; $i -lt $parts.Count; $i++) {
        $last = $i -eq $parts.Count - 1
        $cur = $cur + $sep + $parts[$i]
        try { $attr = [int][IO.File]::GetAttributes((Get-LongPath $cur)) }
        catch [IO.IOException] { if ($last) { return 'no longer exists' } else { return 'parent no longer exists' } }
        catch { return 'unreadable: ' + $_.Exception.Message }
        if (-not $last) {
            if (($attr -band 0x400) -ne 0) { return 'parent is now a reparse point' }
            continue
        }
        $v = Get-EntryVerdict $parts[$i] $attr
        if ($v -eq 'reparse') { return 'is now a reparse point' }
        if ($v -ne '') { return $v }
        $isDir = ($attr -band 0x10) -ne 0
        if ($isDir -and $Finding.Kind -ne 'dir') { return 'is no longer a file' }
        if (-not $isDir -and $Finding.Kind -eq 'dir') { return 'is no longer a directory' }
    }
    $null
}

# Bottom-up delete over \\?\ paths. Clears ReadOnly first; a reparse point is removed as a link and never entered.
# ponytail: re-check and delete are separate calls, so a swap in between is still possible (no handle-based delete from .NET).
function Remove-JunkPermanent {
    param([string]$FullPath)
    $clear = {
        param($p, [int]$a)
        if (($a -band 1) -ne 0) { [IO.File]::SetAttributes($p, [IO.FileAttributes]($a -band (-bnot 1))) }
    }
    $dirs = New-Object 'System.Collections.Generic.List[string]'
    $stack = New-Object 'System.Collections.Generic.Stack[string]'
    $stack.Push($FullPath)
    $sep = [IO.Path]::DirectorySeparatorChar
    while ($stack.Count -gt 0) {
        $p = Get-LongPath $stack.Pop()
        $a = [int][IO.File]::GetAttributes($p)
        $isDir = ($a -band 0x10) -ne 0
        if (($a -band 0x400) -ne 0) {
            & $clear $p $a
            # Windows removes a directory link with RemoveDirectory; elsewhere a link is unlinked like a file.
            if ($isDir -and $script:IsWindows5) { [IO.Directory]::Delete($p, $false) } else { [IO.File]::Delete($p) }
        } elseif ($isDir) {
            $dirs.Add($p)
            foreach ($e in (New-Object IO.DirectoryInfo $p).EnumerateFileSystemInfos()) { $stack.Push($p + $sep + $e.Name) }
        } else {
            & $clear $p $a
            [IO.File]::Delete($p)
        }
    }
    # Children were discovered after their parent, so the reverse order empties them first.
    for ($i = $dirs.Count - 1; $i -ge 0; $i--) {
        & $clear $dirs[$i] ([int][IO.File]::GetAttributes($dirs[$i]))
        [IO.Directory]::Delete($dirs[$i], $false)
    }
}

# 0x0040 ALLOWUNDO | 0x0400 NOERRORUI | 0x0004 SILENT | 0x0010 NOCONFIRMATION, plus 0x4000 WANTNUKEWARNING unless --yes.
function Get-RecycleFlags {
    param([bool]$Yes)
    $f = 0x0454
    if (-not $Yes) { $f = $f -bor 0x4000 }
    $f
}

# SHFileOperationW rejects \\?\ paths (rc 0x7C), so this takes the plain FullPath.
function Invoke-Recycle {
    param([string]$Path, [int]$Flags)
    if (-not $script:IsWindows5) { throw 'the Recycle Bin is Windows only' }
    if (-not ('JunkShell' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class JunkShell {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct SHFILEOPSTRUCT {
        public IntPtr hwnd; public uint wFunc; public string pFrom; public string pTo; public ushort fFlags;
        [MarshalAs(UnmanagedType.Bool)] public bool fAnyOperationsAborted;
        public IntPtr hNameMappings; public string lpszProgressTitle;
    }
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    static extern int SHFileOperationW(ref SHFILEOPSTRUCT op);
    public static int Delete(string path, ushort flags, out bool aborted) {
        SHFILEOPSTRUCT op = new SHFILEOPSTRUCT();
        op.wFunc = 3; op.pFrom = path + "\0"; op.fFlags = flags;
        int rc = SHFileOperationW(ref op);
        aborted = op.fAnyOperationsAborted;
        return rc;
    }
}
'@
    }
    $aborted = $false
    $rc = [JunkShell]::Delete($Path, [uint16]$Flags, [ref]$aborted)
    [pscustomobject]@{ Ok = ($rc -eq 0 -and -not $aborted); Code = $rc }
}

# Returns Removed (findings), Skipped and Failed (finding + reason). One item at a time; one error never stops the rest.
function Invoke-CleanItems {
    param($Findings, [string]$HomeRoot, [string]$ExtraRoot, [bool]$Yes, [bool]$Permanent)
    $out = @{ Removed = @(); Skipped = @(); Failed = @() }
    foreach ($f in @($Findings)) {
        $root = $null
        if ($f.Tier -ne 'junk') { $why = 'not Junk tier' }
        else {
            $root = Get-FindingRoot $f $HomeRoot $ExtraRoot
            if ($null -eq $root) { $why = 'path is not under the root' } else { $why = Test-CleanTarget $f $root }
        }
        if ($why) { $out.Skipped += [pscustomobject]@{ finding = $f; reason = $why }; continue }
        try {
            if ($Permanent) { Remove-JunkPermanent $f.FullPath }
            else {
                $r = Invoke-Recycle -Path $f.FullPath -Flags (Get-RecycleFlags $Yes)
                if (-not $r.Ok) { throw ('Recycle Bin call failed (0x{0:X})' -f $r.Code) }
            }
            $out.Removed += $f
        } catch {
            $out.Failed += [pscustomobject]@{ finding = $f; reason = $_.Exception.Message }
        }
    }
    $out
}

function Get-TotalSize {
    param($Findings)
    $n = [long]0
    foreach ($f in @($Findings)) { $n += $f.Size }
    $n
}

function Format-CleanPlan {
    param($Remove, $Skipped)
    $sb = New-Object Text.StringBuilder
    [void]$sb.Append("To remove:`n")
    foreach ($f in @($Remove | Sort-Object -Property Size -Descending)) {
        [void]$sb.Append('  ').Append((Format-JunkSize $f.Size).PadLeft(8)).Append('  ~\').Append((ConvertTo-SafeText $f.Path)).Append("`n")
    }
    [void]$sb.Append("Skipped:`n")
    foreach ($s in @($Skipped)) {
        [void]$sb.Append('  ~\').Append((ConvertTo-SafeText $s.finding.Path)).Append('  (skipped: ').Append((ConvertTo-SafeText $s.reason)).Append(")`n")
    }
    [void]$sb.Append("Total: $(@($Remove).Count) items (up to $(Format-JunkSize (Get-TotalSize $Remove)))")
    $sb.ToString()
}

function Get-CleanPrompt {
    param([int]$Count, [long]$Bytes, [bool]$Permanent)
    $size = Format-JunkSize $Bytes
    if ($Permanent) { return "Permanently delete $Count items (up to $size)? This cannot be undone. [y/N] " }
    "Move $Count items (up to $size) to the Recycle Bin? Items too large for it are deleted permanently. [y/N] "
}

function Test-CleanConfirmed {
    param([string]$Answer)
    if (-not $Answer) { return $false }
    $a = $Answer.Trim().ToLowerInvariant()
    $a -eq 'y' -or $a -eq 'yes'
}

function Get-CleanSummary {
    param($Outcome, [int]$ExtraSkipped, [bool]$Permanent)
    $size = Format-JunkSize (Get-TotalSize $Outcome.Removed)
    $skipped = @($Outcome.Skipped).Count + $ExtraSkipped
    if ($Permanent) { $s = "Deleted $(@($Outcome.Removed).Count) items (up to $size); " }
    else { $s = "Moved $(@($Outcome.Removed).Count) items (up to $size) to the Recycle Bin; " }
    $s += "$skipped skipped; $(@($Outcome.Failed).Count) failed."
    if (-not $Permanent) { $s += "`nSpace is freed when you empty the Recycle Bin." }
    $s
}

function Get-CleanExitCode {
    param($Outcome)
    if (@($Outcome.Failed).Count -eq 0) { 0 } else { 1 }
}

# Thin wrappers so tests can mock the console, stdin and the process list.
function Write-JunkLine { param([string]$Text) $host.UI.WriteLine($Text) }
function Test-InputRedirected { [Console]::IsInputRedirected }
function Read-CleanAnswer { param([string]$Prompt) Read-Host -Prompt $Prompt.TrimEnd() }
function Get-RunningProcessNames { @(Get-Process | ForEach-Object { $_.ProcessName }) }

# $Options comes from ConvertFrom-CleanArgs. Returns the exit code.
function Invoke-JunkClean {
    param($Options, [string]$Root, [string]$ExtraRoot, [datetime]$Now)
    if (-not $Options.Yes -and (Test-InputRedirected)) {
        $host.UI.WriteErrorLine('Refusing to clean without a terminal to confirm on; pass --yes to skip the prompt.')
        return 2
    }
    $result = Invoke-JunkScan -Root $Root -Now $Now -ExtraRoot $ExtraRoot
    $plan = Get-CleanPlan $result @($Options.Sections) @(Get-RunningProcessNames)
    if (@($plan.remove).Count -eq 0 -and @($plan.skipped).Count -eq 0) { Write-JunkLine 'Nothing to clean.'; return 0 }
    Write-JunkLine (Format-CleanPlan $plan.remove $plan.skipped)
    if (@($plan.remove).Count -eq 0) { return 0 }
    if (-not $Options.Yes) {
        $prompt = Get-CleanPrompt @($plan.remove).Count (Get-TotalSize $plan.remove) $Options.Permanent
        if (-not (Test-CleanConfirmed (Read-CleanAnswer $prompt))) { Write-JunkLine 'Aborted; nothing removed.'; return 0 }
    }
    $out = Invoke-CleanItems $plan.remove $Root $ExtraRoot $Options.Yes $Options.Permanent
    foreach ($s in $out.Skipped) { Write-JunkLine ('skipped ~\' + (ConvertTo-SafeText $s.finding.Path) + ': ' + (ConvertTo-SafeText $s.reason)) }
    foreach ($s in $out.Failed) { Write-JunkLine ('failed ~\' + (ConvertTo-SafeText $s.finding.Path) + ': ' + (ConvertTo-SafeText $s.reason)) }
    Write-JunkLine (Get-CleanSummary $out @($plan.skipped).Count $Options.Permanent)
    Get-CleanExitCode $out
}

# Returns the exit code.
function Main {
    param([string[]]$Arguments, [string]$LanguageMode = [string]$ExecutionContext.SessionState.LanguageMode)
    # Language check first, and Test-Elevated only after it: CLM blocks WindowsPrincipal. $host.UI works under CLM.
    $block = Get-StartupBlock -LanguageMode $LanguageMode -Elevated $false
    if (-not $block) { $block = Get-StartupBlock -LanguageMode $LanguageMode -Elevated (Test-Elevated) }
    if ($block) { $host.UI.WriteErrorLine($block); return 3 }
    try { [Console]::OutputEncoding = New-Object Text.UTF8Encoding $false } catch { Write-Verbose 'console encoding not set' }
    if (@($Arguments).Count -gt 0) {
        if ($Arguments[0] -eq 'clean') {
            $o = ConvertFrom-CleanArgs @($Arguments | Select-Object -Skip 1)
            if (-not $o.Ok) { $host.UI.WriteErrorLine($o.Message); return 2 }
            $root = $env:USERPROFILE
            if (-not $root) { $root = $HOME }
            return (Invoke-JunkClean $o $root ([string](Get-DownloadsFolder)) ([datetime]::UtcNow))
        }
        $host.UI.WriteErrorLine('Usage: junk'); return 2
    }
    $root = $env:USERPROFILE
    if (-not $root) { $root = $HOME }
    [Console]::Out.Write((Format-JunkReport (Invoke-JunkScan -Root $root -Now ([datetime]::UtcNow)) ([datetime]::UtcNow)))
    0
}

# Dot-sourcing (. .\junk.ps1) loads the functions without running Main.
if ($MyInvocation.InvocationName -ne '.') {
    exit (Main -Arguments $args)
}
