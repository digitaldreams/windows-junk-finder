# Windows fact finder for research section 8 (T2). Run on Windows PowerShell 5.1:
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\probe.ps1
# Fixtures live only under %TEMP%\junk-probe and are removed at the end.
Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

function Format-ProbeLine {
    param(
        [Parameter(Mandatory)][ValidateSet('PASS', 'FAIL', 'INFO')][string]$Status,
        [Parameter(Mandatory)][string]$Id,
        [Parameter(Mandatory)][string]$Description,
        [AllowEmptyString()][string]$Detail = ''
    )
    $one = $Detail -replace '\s*[\r\n]+\s*', ' '
    '{0} {1} {2}: {3}' -f $Status, $Id, $Description, $one
}

function New-ProbeResult {
    param([string]$Status, [string]$Detail)
    @{ Status = $Status; Detail = $Detail }
}

function Get-ProbeError {
    param($ErrorRecord)
    $e = $ErrorRecord.Exception
    if ($e.InnerException -and $e.GetType().Name -eq 'MethodInvocationException') { $e = $e.InnerException }
    '{0}: {1}' -f $e.GetType().FullName, $e.Message
}

# Runs one check. Body returns a string (PASS detail) or a New-ProbeResult hashtable.
# Any exception becomes FAIL with type and message; it never stops later checks.
function Invoke-ProbeCheck {
    param([string]$Id, [string]$Description, [scriptblock]$Body)
    try {
        $r = & $Body
        if ($r -is [hashtable]) { $s = $r.Status; $d = $r.Detail }
        else { $s = 'PASS'; $d = [string]($r -join ' ') }
    } catch {
        $s = 'FAIL'; $d = Get-ProbeError $_
    }
    Format-ProbeLine -Status $s -Id $Id -Description $Description -Detail $d
}

function Remove-ProbeRoot {
    param([string]$Path)
    # Safety: only ever delete a folder literally named junk-probe inside TEMP.
    if (-not $env:TEMP -or $Path -ne ($env:TEMP + '\junk-probe')) { throw "refusing to clean $Path" }
    if (-not [IO.Directory]::Exists($Path)) { return }
    if (([IO.File]::GetAttributes($Path) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "refusing to clean ${Path}: root is a reparse point" }
    $link = $Path + '\c4\link'
    if ([IO.Directory]::Exists($link)) { try { [IO.Directory]::Delete($link, $false) } catch { Write-Verbose $_ } }
    $ro = $Path + '\c5\ro.txt'
    if ([IO.File]::Exists($ro)) { try { [IO.File]::SetAttributes($ro, [IO.FileAttributes]::Normal) } catch { Write-Verbose $_ } }
    try { [IO.Directory]::Delete('\\?\' + $Path, $true) } catch {
        try { [IO.Directory]::Delete($Path, $true) } catch {
            Format-ProbeLine -Status INFO -Id 'cleanup' -Description 'could not remove fixtures' -Detail ("$Path " + (Get-ProbeError $_))
        }
    }
}

function Write-ProbeHeader {
    $lines = @()
    $lines += '# PSVersion: ' + $PSVersionTable.PSVersion + ' CLR ' + $PSVersionTable.CLRVersion
    try {
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        $lines += '# OS: ' + $cv.ProductName + ' build ' + $cv.CurrentBuild + '.' + $cv.UBR + ' 64bitProcess=' + [Environment]::Is64BitProcess
    } catch { $lines += '# OS: unreadable ' + [Environment]::OSVersion.VersionString }
    try {
        $lp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem').LongPathsEnabled
        $lines += '# LongPathsEnabled: ' + $lp
    } catch { $lines += '# LongPathsEnabled: not set/unreadable' }
    $lines += '# LanguageMode: ' + $ExecutionContext.SessionState.LanguageMode
    $lines | ForEach-Object { $_ -replace '[\r\n]+', ' ' }
}

function Test-PrefixPathChecks {
    $dir = $script:Root + '\c1'
    [void][IO.Directory]::CreateDirectory($dir + '\sub')
    [IO.File]::WriteAllText($dir + '\a.txt', 'x')
    foreach ($v in @(@('std', ''), @('pfx', '\\?\'))) {
        $tag = $v[0]; $pre = $v[1]; $label = if ($pre) { '\\?\ prefix' } else { 'plain' }
        Invoke-ProbeCheck "1a-$tag" "Directory.Exists ($label)" {
            if ([IO.Directory]::Exists($pre + $dir)) { 'True' } else { New-ProbeResult FAIL 'returned False' }
        }
        Invoke-ProbeCheck "1b-$tag" "EnumerateFileSystemInfos ($label)" {
            $di = New-Object IO.DirectoryInfo ($pre + $dir)
            $n = @($di.EnumerateFileSystemInfos() | ForEach-Object { $_.Name }) -join ','
            if ($n -eq 'a.txt,sub' -or $n -eq 'sub,a.txt') { $n } else { New-ProbeResult FAIL "unexpected entries: $n" }
        }
        Invoke-ProbeCheck "1c-$tag" "File.Delete ($label)" {
            $f = $dir + "\del-$tag.txt"
            [IO.File]::WriteAllText($f, 'x')
            [IO.File]::Delete($pre + $f)
            if (-not [IO.File]::Exists($f)) { 'deleted' } else { New-ProbeResult FAIL 'file still exists' }
        }
        Invoke-ProbeCheck "1d-$tag" "DirectoryInfo.Delete ($label)" {
            $d = $dir + "\empty-$tag"
            [void][IO.Directory]::CreateDirectory($d)
            (New-Object IO.DirectoryInfo ($pre + $d)).Delete()
            if (-not [IO.Directory]::Exists($d)) { 'deleted' } else { New-ProbeResult FAIL 'dir still exists' }
        }
    }
    Invoke-ProbeCheck '1e' 'AppContext switches' {
        $out = foreach ($n in 'Switch.System.IO.UseLegacyPathHandling', 'Switch.System.IO.BlockLongPaths') {
            $val = $false
            if ([AppContext]::TryGetSwitch($n, [ref]$val)) { "$n=$val" } else { "$n=not set" }
        }
        New-ProbeResult INFO ($out -join '; ')
    }
}

function Test-LongPathChecks {
    $long = $script:Root + '\c2'
    1..5 | ForEach-Object { $long += '\' + ('d' * 60) }
    $file = $long + '\f.txt'
    Invoke-ProbeCheck '2a' ('create dir+file via \\?\ prefix, path length ' + $file.Length) {
        [void][IO.Directory]::CreateDirectory('\\?\' + $long)
        [IO.File]::WriteAllText('\\?\' + $file, 'x')
        'created'
    }
    foreach ($v in @(@('std', ''), @('pfx', '\\?\'))) {
        $tag = $v[0]; $pre = $v[1]; $label = if ($pre) { '\\?\ prefix' } else { 'plain' }
        Invoke-ProbeCheck "2b-$tag" "Directory.Exists+File.Exists on long path ($label)" {
            $a = [IO.Directory]::Exists($pre + $long); $b = [IO.File]::Exists($pre + $file)
            if ($a -and $b) { 'True/True' } else { New-ProbeResult FAIL "dir=$a file=$b" }
        }
        Invoke-ProbeCheck "2c-$tag" "EnumerateFileSystemInfos on long path ($label)" {
            $n = @((New-Object IO.DirectoryInfo ($pre + $long)).EnumerateFileSystemInfos()).Count
            "$n entries"
        }
        Invoke-ProbeCheck "2d-$tag" "File.WriteAllText+Delete on long path ($label)" {
            $f = $long + "\w-$tag.txt"
            [IO.File]::WriteAllText($pre + $f, 'x')
            [IO.File]::Delete($pre + $f)
            'written and deleted'
        }
    }
}

function Test-RecycleChecks {
    $dir = $script:Root + '\c3'
    [void][IO.Directory]::CreateDirectory($dir)
    # C# 5, kept tiny. SHFILEOPSTRUCT needs Pack=1 only on 32-bit; the default packing is right on 64-bit.
    $cs = @'
using System;
using System.Runtime.InteropServices;
public static class ProbeShell {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SHFILEOPSTRUCT {
        public IntPtr hwnd; public uint wFunc; public string pFrom; public string pTo;
        public ushort fFlags; public bool fAnyOperationsAborted; public IntPtr hNameMappings; public string lpszProgressTitle;
    }
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    static extern int SHFileOperationW(ref SHFILEOPSTRUCT op);
    public static int Recycle(string path, out bool aborted) {
        SHFILEOPSTRUCT op = new SHFILEOPSTRUCT();
        op.wFunc = 3; // FO_DELETE
        op.pFrom = path + "\0"; // double-null terminated with the marshalled terminator
        op.fFlags = 0x454; // ALLOWUNDO | NOCONFIRMATION | SILENT | NOERRORUI
        int rc = SHFileOperationW(ref op);
        aborted = op.fAnyOperationsAborted;
        return rc;
    }
}
'@
    Invoke-ProbeCheck '3a' 'Add-Type SHFileOperationW shim (Defender/AMSI open question)' {
        Add-Type -TypeDefinition $cs
        'compiled'
    }
    Format-ProbeLine -Status INFO -Id '3n' -Description 'note' -Detail 'checks 3b/3c recycle two tiny fixture files; those items stay in your Recycle Bin, delete them by hand'
    foreach ($v in @(@('plain', ''), @('pfx', '\\?\'))) {
        $tag = $v[0]; $pre = $v[1]
        Invoke-ProbeCheck "3-$tag" ("SHFileOperationW recycle, " + $(if ($pre) { '\\?\ path' } else { 'plain path' })) {
            if (-not ('ProbeShell' -as [type])) { return New-ProbeResult FAIL 'skipped: shim not compiled (see 3a)' }
            $f = $dir + "\recycle-me-$tag.txt"
            [IO.File]::WriteAllText($f, 'junk-probe fixture')
            $aborted = $false
            $rc = [ProbeShell]::Recycle($pre + $f, [ref]$aborted)
            $gone = -not [IO.File]::Exists($f)
            $detail = ('rc=0x{0:X} aborted={1} sourceGone={2}' -f $rc, $aborted, $gone)
            if ($rc -eq 0 -and -not $aborted -and $gone) { $detail } else { New-ProbeResult FAIL $detail }
        }
    }
}

function Test-JunctionChecks {
    $dir = $script:Root + '\c4'
    $target = $dir + '\target'; $link = $dir + '\link'; $keep = $target + '\keep.txt'
    Invoke-ProbeCheck '4a' 'mklink /J creates junction' {
        [void][IO.Directory]::CreateDirectory($target)
        [IO.File]::WriteAllText($keep, 'x')
        $ErrorActionPreference = 'Continue'
        $out = (cmd /c "mklink /J `"$link`" `"$target`"" 2>&1 | Out-String)
        $code = $LASTEXITCODE
        $ErrorActionPreference = 'Stop'
        if ($code -eq 0 -and [IO.Directory]::Exists($link)) { "exit=$code " + $out.Trim() } else { New-ProbeResult FAIL "exit=$code $out" }
    }
    Invoke-ProbeCheck '4b' 'junction Attributes has ReparsePoint' {
        $a = (New-Object IO.DirectoryInfo $link).Attributes
        if (($a -band [IO.FileAttributes]::ReparsePoint) -ne 0) { "$a" } else { New-ProbeResult FAIL "attributes=$a" }
    }
    Invoke-ProbeCheck '4c' 'Directory.Delete(link,$false) removes link only, target survives' {
        [IO.Directory]::Delete($link, $false)
        $s = ('linkGone={0} targetKept={1} fileKept={2}' -f (-not [IO.Directory]::Exists($link)), [IO.Directory]::Exists($target), [IO.File]::Exists($keep))
        if ($s -eq 'linkGone=True targetKept=True fileKept=True') { $s } else { New-ProbeResult FAIL $s }
    }
}

function Test-ReadOnlyChecks {
    $dir = $script:Root + '\c5'; $f = $dir + '\ro.txt'
    [void][IO.Directory]::CreateDirectory($dir)
    [IO.File]::WriteAllText($f, 'x')
    [IO.File]::SetAttributes($f, [IO.FileAttributes]::ReadOnly)
    Invoke-ProbeCheck '5a' 'File.Delete on ReadOnly file is refused' {
        try { [IO.File]::Delete($f) } catch { return ('refused: ' + (Get-ProbeError $_)) }
        New-ProbeResult FAIL 'delete succeeded on a ReadOnly file'
    }
    Invoke-ProbeCheck '5b' 'clear ReadOnly then File.Delete succeeds' {
        [IO.File]::SetAttributes($f, [IO.FileAttributes]::Normal)
        [IO.File]::Delete($f)
        if (-not [IO.File]::Exists($f)) { 'deleted' } else { New-ProbeResult FAIL 'file still exists' }
    }
}

function Test-EnvironmentChecks {
    Invoke-ProbeCheck '6a' 'language mode' { New-ProbeResult INFO ([string]$ExecutionContext.SessionState.LanguageMode) }
    Invoke-ProbeCheck '6b' 'elevated (Administrator)' {
        $p = New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())
        New-ProbeResult INFO ([string]$p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    }
    Invoke-ProbeCheck '6c' '[Console]::IsInputRedirected' { New-ProbeResult INFO ([string][Console]::IsInputRedirected) }
}

function Test-DefaultPathChecks {
    $local = $env:LOCALAPPDATA; $roam = $env:APPDATA
    $paths = @(
        @('7a', 'Composer (Local)', ($local + '\Composer')),
        @('7b', 'Composer (Roaming)', ($roam + '\Composer')),
        @('7c', 'Yarn\Cache', ($local + '\Yarn\Cache')),
        @('7d', 'CrashDumps', ($local + '\CrashDumps')),
        @('7e', 'npm-cache', ($local + '\npm-cache')),
        @('7f', 'pip\Cache', ($local + '\pip\Cache')),
        @('7g', 'NuGet\v3-cache', ($local + '\NuGet\v3-cache')),
        @('7h', 'go-build', ($local + '\go-build'))
    )
    foreach ($p in $paths) {
        $pp = $p[2]
        Invoke-ProbeCheck $p[0] ('exists: ' + $p[1]) { New-ProbeResult INFO ("$pp -> " + [IO.Directory]::Exists($pp)) }
    }
    Invoke-ProbeCheck '7i' 'Downloads known folder' {
        $key = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
        $prop = $key.PSObject.Properties['{374DE290-123F-4565-9164-39C4925E467B}']
        if (-not $prop) { return New-ProbeResult INFO 'not set in User Shell Folders (default %USERPROFILE%\Downloads applies)' }
        $raw = $prop.Value
        $res = [Environment]::ExpandEnvironmentVariables($raw)
        New-ProbeResult INFO ("raw=$raw resolved=$res exists=" + [IO.Directory]::Exists($res) + ' underProfile=' + $res.StartsWith($env:USERPROFILE + '\', [StringComparison]::OrdinalIgnoreCase))
    }
}

# A throw in a group's setup becomes one FAIL line; the next group still runs.
function Invoke-ProbeGroup {
    param([string]$Name, [scriptblock]$Group)
    try { & $Group } catch {
        Format-ProbeLine -Status FAIL -Id "setup-$Name" -Description 'group setup failed, rest of group skipped' -Detail (Get-ProbeError $_)
    }
}

function Invoke-ProbeMain {
    if ($env:OS -ne 'Windows_NT') { 'probe.ps1 only runs on Windows'; return }
    $script:Root = $env:TEMP + '\junk-probe'
    Write-ProbeHeader
    try {
        Remove-ProbeRoot $script:Root
        [void][IO.Directory]::CreateDirectory($script:Root)
        Invoke-ProbeGroup 'prefix' { Test-PrefixPathChecks }
        Invoke-ProbeGroup 'longpath' { Test-LongPathChecks }
        Invoke-ProbeGroup 'recycle' { Test-RecycleChecks }
        Invoke-ProbeGroup 'junction' { Test-JunctionChecks }
        Invoke-ProbeGroup 'readonly' { Test-ReadOnlyChecks }
        Invoke-ProbeGroup 'env' { Test-EnvironmentChecks }
        Invoke-ProbeGroup 'paths' { Test-DefaultPathChecks }
    } catch {
        Format-ProbeLine -Status FAIL -Id 'setup' -Description 'probe aborted' -Detail (Get-ProbeError $_)
    } finally {
        try { Remove-ProbeRoot $script:Root } catch {
            Format-ProbeLine -Status FAIL -Id 'cleanup' -Description 'cleanup refused or failed' -Detail (Get-ProbeError $_)
        }
    }
    '# done. Fixtures removed. Recycled fixture files (3-plain/3-pfx) remain in the Recycle Bin.'
}

# Dot-sourcing (. .\tools\probe.ps1) loads the functions without running the checks.
if ($MyInvocation.InvocationName -ne '.') {
    Invoke-ProbeMain
}
