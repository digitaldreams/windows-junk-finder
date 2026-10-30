# Windows-only checks: junctions, \\?\ long paths, ReadOnly, the real Recycle Bin call.
# Every It is tagged Windows and skipped elsewhere. The CI runner is elevated, which is fine here: nothing calls Main.
BeforeAll {
    . (Join-Path (Join-Path $PSScriptRoot '..') 'junk.ps1')
    $script:Now = [DateTime]::UtcNow.AddDays(100)
    function Add-Dir($p) { New-Item -ItemType Directory -Force -Path $p | Out-Null }
    function Add-File($p, [double]$ModDays = 0) {
        Add-Dir (Split-Path $p -Parent)
        [IO.File]::WriteAllText($p, "x`n")
        [IO.File]::SetLastWriteTimeUtc($p, $script:Now.AddDays(-$ModDays))
    }
    function Add-Project($home_, $rel) {
        Add-File (Join-Path $home_ "$rel/package.json") 60
        Add-File (Join-Path $home_ "$rel/package-lock.json") 60
        Add-File (Join-Path $home_ "$rel/node_modules/a/index.js") 60
    }
    # Directory junction (no admin needed); remembered so AfterEach can unlink it before Pester cleans TestDrive.
    function Add-Junction($path, $target) {
        $p = $path -replace '/', '\'
        $t = $target -replace '/', '\'
        & cmd.exe /c mklink /J $p $t | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "mklink /J failed for $p" }
        $script:Links += $p
    }
    function NewF($full, $kind = 'file') { [pscustomobject]@{ Path = 'x'; FullPath = $full; Kind = $kind; Size = [long]1; Tier = 'junk' } }
}

Describe 'Windows' -Tag Windows {
    BeforeEach {
        $script:Links = @()
        $script:H = Join-Path $TestDrive ('w' + [guid]::NewGuid().ToString('N'))
        Add-Dir $script:H
    }
    AfterEach {
        foreach ($l in $script:Links) { if ([IO.Directory]::Exists($l)) { [IO.Directory]::Delete($l, $false) } }
    }

    It 'documents the supported process: 64-bit' -Skip:($env:OS -ne 'Windows_NT') {
        [Environment]::Is64BitProcess | Should -BeTrue
    }

    It 'Test-FixedDrive is true for the system drive' -Skip:($env:OS -ne 'Windows_NT') {
        Test-FixedDrive ($env:SystemDrive + '\') | Should -BeTrue
    }

    It 'the scanner does not follow a junction to an outside dir, and a junction loop ends' -Skip:($env:OS -ne 'Windows_NT') {
        $outside = Join-Path $TestDrive ('o' + [guid]::NewGuid().ToString('N'))
        Add-Project $outside 'proj'
        Add-Project $script:H 'code/app'
        Add-Junction (Join-Path $script:H 'link') $outside
        Add-Junction (Join-Path $script:H 'code\loop') $script:H
        $r = Invoke-JunkScan -Root $script:H -Now $script:Now
        @($r.Findings).Count | Should -Be 1
        $r.Findings[0].Path | Should -Be 'code\app\node_modules'
        @($r.Skipped).Count | Should -Be 0
    }

    It 'Test-CleanTarget rejects an item whose parent became a junction, and a junction item' -Skip:($env:OS -ne 'Windows_NT') {
        $root = Join-Path $script:H 'root'
        Add-File (Join-Path $script:H 'elsewhere\a.tmp')
        Add-Dir $root
        Add-Junction (Join-Path $root 'Temp') (Join-Path $script:H 'elsewhere')
        Test-CleanTarget (NewF (Join-Path $root 'Temp\a.tmp')) $root | Should -BeExactly 'parent is now a reparse point'
        Test-CleanTarget (NewF (Join-Path $root 'Temp') 'dir') $root | Should -BeExactly 'is now a reparse point'
    }

    It 'Test-CleanTarget rejects a name Win32 cannot address (trailing dot, made through \\?\)' -Skip:($env:OS -ne 'Windows_NT') {
        $dir = Join-Path $script:H 'AppData\Local\Temp'
        Add-Dir $dir
        $odd = '\\?\' + $dir + '\x.'
        [IO.File]::WriteAllText($odd, 'x')
        try { Test-CleanTarget (NewF ($dir + '\x.')) $script:H | Should -BeExactly 'unaddressable name' }
        finally { [IO.File]::Delete($odd) }
    }

    It 'finds a stale node_modules at a path over 260 characters and Remove-JunkPermanent removes it' -Skip:($env:OS -ne 'Windows_NT') {
        $top = Join-Path $script:H 'lp'
        $proj = $top
        foreach ($i in 1..5) { $proj = $proj + '\' + ('d' * 50) }
        $nm = $proj + '\node_modules'
        $nm.Length | Should -BeGreaterThan 260
        try {
            foreach ($f in @(($proj + '\package.json'), ($proj + '\package-lock.json'), ($nm + '\a\index.js'))) {
                [void][IO.Directory]::CreateDirectory('\\?\' + $f.Substring(0, $f.LastIndexOf('\')))
                [IO.File]::WriteAllText('\\?\' + $f, "x`n")
                [IO.File]::SetLastWriteTimeUtc('\\?\' + $f, $script:Now.AddDays(-60))
            }
            $r = Invoke-JunkScan -Root $script:H -Now $script:Now
            @($r.Findings).Count | Should -Be 1
            $r.Findings[0].RuleId | Should -Be 'D5'
            $r.Findings[0].Tier | Should -Be 'junk'
            $r.Findings[0].FullPath | Should -BeExactly $nm
            @($r.Skipped).Count | Should -Be 0
            Remove-JunkPermanent $r.Findings[0].FullPath
            [IO.Directory]::Exists('\\?\' + $nm) | Should -BeFalse
            [IO.File]::Exists('\\?\' + $proj + '\package.json') | Should -BeTrue
        }
        finally {
            # Pester's own TestDrive cleanup may choke on over-long paths.
            if ([IO.Directory]::Exists('\\?\' + $top)) { Remove-JunkPermanent $top }
        }
    }

    It 'Remove-JunkPermanent removes a ReadOnly file and a ReadOnly directory inside a tree' -Skip:($env:OS -ne 'Windows_NT') {
        Add-File (Join-Path $script:H 't\ro\f.txt')
        Add-File (Join-Path $script:H 't\rofile.txt')
        [IO.File]::SetAttributes((Join-Path $script:H 't\ro\f.txt'), [IO.FileAttributes]::ReadOnly)
        [IO.File]::SetAttributes((Join-Path $script:H 't\rofile.txt'), [IO.FileAttributes]::ReadOnly)
        [IO.File]::SetAttributes((Join-Path $script:H 't\ro'), [IO.FileAttributes]::Directory -bor [IO.FileAttributes]::ReadOnly)
        Remove-JunkPermanent (Join-Path $script:H 't')
        [IO.Directory]::Exists((Join-Path $script:H 't')) | Should -BeFalse
    }

    It 'Remove-JunkPermanent removes a junction inside the tree as a link only' -Skip:($env:OS -ne 'Windows_NT') {
        Add-File (Join-Path $script:H 'keep\important.txt')
        Add-File (Join-Path $script:H 't\a.txt')
        Add-Junction (Join-Path $script:H 't\jl') (Join-Path $script:H 'keep')
        Remove-JunkPermanent (Join-Path $script:H 't')
        [IO.Directory]::Exists((Join-Path $script:H 't')) | Should -BeFalse
        [IO.File]::Exists((Join-Path $script:H 'keep\important.txt')) | Should -BeTrue
    }

    It 'Invoke-Recycle really recycles one file (rc 0, not aborted, source gone)' -Skip:($env:OS -ne 'Windows_NT') {
        $f = Join-Path $script:H 'recycle-me.txt'
        Add-File $f
        $r = Invoke-Recycle -Path $f -Flags (Get-RecycleFlags $true)
        $r.Code | Should -Be 0
        $r.Ok | Should -BeTrue
        [IO.File]::Exists($f) | Should -BeFalse
    }
    # ponytail: no child-process CLM test. __PSLockdownPolicy does not force CLM on the runner (CI run 41055797773);
    # the guard is covered on real 5.1 by the CLM runspace test in Report.Tests.ps1.
}
