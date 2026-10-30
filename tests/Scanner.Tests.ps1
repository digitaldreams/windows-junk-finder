BeforeDiscovery {
    $script:NoChmod = ($env:OS -eq 'Windows_NT') -or ((& id -u) -eq '0')
}

BeforeAll {
    $script:NoChmod = ($env:OS -eq 'Windows_NT') -or ((& id -u) -eq '0')
    . (Join-Path (Join-Path $PSScriptRoot '..') 'junk.ps1')
    # Fixtures are created "now" (Created can't be set on Linux), so $Now sits 100 days ahead.
    $script:Now = [DateTime]::UtcNow.AddDays(100)
    function Add-Dir($p) { New-Item -ItemType Directory -Force -Path $p | Out-Null }
    function Add-File($p, [double]$ModDays = 0) {
        Add-Dir (Split-Path $p -Parent)
        Set-Content -LiteralPath $p -Value 'x'
        [IO.File]::SetLastWriteTimeUtc($p, $script:Now.AddDays(-$ModDays))
    }
    function Add-Big($p) { # sparse 600 MB, 400 d old
        Add-Dir (Split-Path $p -Parent)
        $fs = [IO.File]::Create($p); $fs.SetLength(600MB); $fs.Dispose()
        [IO.File]::SetLastWriteTimeUtc($p, $script:Now.AddDays(-400))
    }
    function Add-Project($home_, $rel) { # a stale node_modules with a lock file
        Add-File (Join-Path $home_ "$rel/package.json") 60
        Add-File (Join-Path $home_ "$rel/package-lock.json") 60
        Add-File (Join-Path $home_ "$rel/node_modules/a/index.js") 60
    }
    function Scan($home_, $extra = $null) {
        if ($extra) { Invoke-JunkScan -Root $home_ -Now $script:Now -ExtraRoot $extra }
        else { Invoke-JunkScan -Root $home_ -Now $script:Now }
    }
}

Describe 'Get-ScanErrorKind' {
    It 'maps exceptions to kinds' -TestCases @(
        @{ E = [UnauthorizedAccessException]::new('x'); K = 'access denied' }
        @{ E = [IO.PathTooLongException]::new('x'); K = 'path too long' }
        @{ E = [IO.IOException]::new('x'); K = 'unreadable' }
        @{ E = [IO.DirectoryNotFoundException]::new('x'); K = 'unreadable' }
        @{ E = [Management.Automation.MethodInvocationException]::new('w', [UnauthorizedAccessException]::new('x')); K = 'access denied' }
    ) {
        Get-ScanErrorKind $E | Should -Be $K
    }
}

Describe 'Get-EntryVerdict' {
    It 'classifies attributes and names' -TestCases @(
        @{ N = 'a'; A = 0x10; V = '' }
        @{ N = 'a'; A = 0x410; V = 'reparse' }
        @{ N = 'a'; A = 0x1000; V = 'cloud-only' }
        @{ N = 'a'; A = 0x40000; V = 'cloud-only' }
        @{ N = 'a'; A = 0x400000; V = 'cloud-only' }
        @{ N = 'a'; A = 0x400400; V = 'cloud-only' }
        @{ N = 'node_modules.'; A = 0x10; V = 'unaddressable name' }
        @{ N = 'node_modules '; A = 0x10; V = 'unaddressable name' }
        @{ N = 'CON'; A = 0x20; V = 'unaddressable name' }
        @{ N = 'nul.txt'; A = 0x20; V = 'unaddressable name' }
        @{ N = 'Com1'; A = 0x20; V = 'unaddressable name' }
        @{ N = 'lpt9.log'; A = 0x20; V = 'unaddressable name' }
        @{ N = 'com0'; A = 0x20; V = '' }
        @{ N = 'console'; A = 0x20; V = '' }
    ) {
        Get-EntryVerdict $N $A | Should -Be $V
    }
}

Describe 'Long path and known-folder helpers' {
    It 'Get-LongPath is a no-op off Windows' -Skip:($env:OS -eq 'Windows_NT') {
        Get-LongPath '/tmp/x' | Should -Be '/tmp/x'
    }
    It 'Get-LongPath prefixes drive and UNC paths' -Tag Windows -Skip:($env:OS -ne 'Windows_NT') {
        Get-LongPath 'C:\Users\u' | Should -Be '\\?\C:\Users\u'
        Get-LongPath '\\srv\share\x' | Should -Be '\\?\UNC\srv\share\x'
        Get-LongPath '\\?\C:\x' | Should -Be '\\?\C:\x'
    }
    It 'Get-DownloadsFolder is $null off Windows' -Skip:($env:OS -eq 'Windows_NT') {
        Get-DownloadsFolder | Should -BeNullOrEmpty
    }
}

Describe 'Test-FixedDrive' {
    It 'UNC paths are never fixed' -TestCases @(
        @{ P = '\\nas\share\Downloads' }, @{ P = '\\?\UNC\nas\share' }
    ) {
        Test-FixedDrive $P | Should -BeFalse
    }
    It 'is true off Windows for a normal path' -Skip:($env:OS -eq 'Windows_NT') {
        Test-FixedDrive '/tmp/x' | Should -BeTrue
    }
}

Describe 'Invoke-JunkScan' {
    BeforeEach {
        $script:H = Join-Path $TestDrive ('h' + [guid]::NewGuid().ToString('N'))
        Add-Dir $script:H
    }
    AfterEach {
        if (-not $script:NoChmod) { & chmod -R 755 $script:H }
    }

    It 'returns Findings and Skipped; finding carries item and match' {
        Add-Project $script:H 'code/app'
        $r = Scan $script:H
        $r.Findings.Count | Should -Be 1
        $f = $r.Findings[0]
        $f.Path | Should -Be 'code\app\node_modules'
        $f.Kind | Should -Be 'dir'
        $f.RuleId | Should -Be 'D5'
        $f.Tier | Should -Be 'junk'
        $f.Category | Should -Be 'Dev junk'
        $f.Size | Should -Be 2
        $f.FullPath | Should -Be (Join-Path (Join-Path (Join-Path $script:H 'code') 'app') 'node_modules')
        @($r.Skipped).Count | Should -Be 0
    }

    It 'counts nested node_modules once' {
        Add-Project $script:H 'code/app'
        Add-File (Join-Path $script:H 'code/app/node_modules/a/node_modules/b/package.json') 60
        Add-File (Join-Path $script:H 'code/app/node_modules/a/node_modules/b/i.js') 60
        $r = Scan $script:H
        @($r.Findings).Count | Should -Be 1
        $r.Findings[0].Size | Should -Be 6
    }

    It 'a 600 MB file inside node_modules gives one D5 and no B1' {
        Add-Project $script:H 'code/app'
        $big = Join-Path $script:H 'code/app/node_modules/a/big.bin'
        $fs = [IO.File]::Create($big); $fs.SetLength(600MB); $fs.Dispose()
        [IO.File]::SetLastWriteTimeUtc($big, $script:Now.AddDays(-400))
        $r = Scan $script:H
        @($r.Findings).Count | Should -Be 1
        $r.Findings[0].RuleId | Should -Be 'D5'
        $r.Findings[0].Size | Should -BeGreaterThan 600000000
    }

    It 'a big old file outside any match is B1 (control)' {
        $big = Join-Path $script:H 'stuff/big.bin'
        Add-Dir (Split-Path $big -Parent)
        $fs = [IO.File]::Create($big); $fs.SetLength(600MB); $fs.Dispose()
        [IO.File]::SetLastWriteTimeUtc($big, $script:Now.AddDays(-400))
        $r = Scan $script:H
        @($r.Findings).Count | Should -Be 1
        $r.Findings[0].RuleId | Should -Be 'B1'
        $r.Findings[0].Path | Should -Be 'stuff\big.bin'
    }

    It 'does not follow a symlink to an outside dir, and a symlink loop ends' {
        $outside = Join-Path $TestDrive ('o' + [guid]::NewGuid().ToString('N'))
        Add-Project $outside 'proj'
        Add-Project $script:H 'code/app'
        New-Item -ItemType SymbolicLink -Path (Join-Path $script:H 'link') -Target $outside | Out-Null
        New-Item -ItemType SymbolicLink -Path (Join-Path $script:H 'code/loop') -Target $script:H | Out-Null
        $r = Scan $script:H
        @($r.Findings).Count | Should -Be 1
        $r.Findings[0].Path | Should -Be 'code\app\node_modules'
        @($r.Skipped).Count | Should -Be 0
    }

    It 'a symlink to a .msi in Downloads gives no finding; a real old .msi does' {
        $real = Join-Path $TestDrive ('m' + [guid]::NewGuid().ToString('N') + '.msi')
        Add-File $real 90
        Add-Dir (Join-Path $script:H 'Downloads')
        New-Item -ItemType SymbolicLink -Path (Join-Path $script:H 'Downloads/link.msi') -Target $real | Out-Null
        @((Scan $script:H).Findings).Count | Should -Be 0
        Add-File (Join-Path $script:H 'Downloads/real.msi') 90
        $r = Scan $script:H
        @($r.Findings).Count | Should -Be 1
        $r.Findings[0].Path | Should -Be 'Downloads\real.msi'
        $r.Findings[0].RuleId | Should -Be 'I1'
    }

    # B1 fixture: matched by a non-hidden rule, so only the skip list (not the D5/D6 guard) can hide it.
    It 'a skip-list dir hides a big old file (B1 would match anywhere else)' -TestCases @(
        @{ P = 'Documents' }, @{ P = 'Desktop' }, @{ P = 'Pictures' }, @{ P = 'Music' }, @{ P = 'Videos' }, @{ P = 'Favorites' }
        @{ P = 'OneDrive - Acme' }, @{ P = 'onedrive' }
        @{ P = '.ssh' }, @{ P = '.gnupg' }, @{ P = '.aws' }, @{ P = '.azure' }, @{ P = '.kube' }
        @{ P = '.config' }, @{ P = '.local' }, @{ P = '.cache' }, @{ P = '.rustup' }, @{ P = 'scoop' }
        @{ P = '.cargo/bin' }, @{ P = '.nuget/packages' }, @{ P = '.pnpm-store' }
        @{ P = 'AppData/Local/Packages' }, @{ P = 'AppData/Local/Programs' }, @{ P = 'AppData/Local/Pnpm' }
        @{ P = 'AppData/Local/Microsoft/WindowsApps' }, @{ P = 'AppData/Local/Microsoft/Outlook' }
        @{ P = 'AppData/Local/Microsoft/Credentials' }, @{ P = 'AppData/Roaming/Microsoft' }
    ) {
        Add-Big (Join-Path $script:H "$P/sub/big.bin")
        $r = Scan $script:H
        @($r.Findings).Count | Should -Be 0
        @($r.Skipped).Count | Should -Be 0
    }

    It 'skip list is exact in path and depth: look-alikes and nested names are still scanned' -TestCases @(
        @{ P = 'AppData/Local/PackagesX' }, @{ P = 'x/Documents' }, @{ P = 'AppData/Local/Packages2/y' }
        @{ P = 'AppData/Local/Microsoft/Other' }, @{ P = 'AppData/Roaming/MicrosoftX' }, @{ P = 'Documents2' }
        @{ P = 'AppData/Local/Programs2' }, @{ P = '.cargo/registry' }, @{ P = 'proj/OneDrive' }
        @{ P = 'AppData/Roaming/Other/Microsoft' }
    ) {
        Add-Big (Join-Path $script:H "$P/big.bin")
        $r = Scan $script:H
        @($r.Findings).Count | Should -Be 1
        $r.Findings[0].RuleId | Should -Be 'B1'
    }

    It 'the walk never lists skip-list dirs (covers dirs the matcher denies anyway)' -TestCases @(
        @{ P = '.pnpm-store' }, @{ P = '.nuget\packages' }, @{ P = 'AppData\Local\pnpm' }, @{ P = 'Documents' }, @{ P = '.cargo\bin' }
    ) {
        Add-File (Join-Path $script:H (($P -replace '\\', '/') + '/f.txt')) 0
        $script:seen = New-Object 'System.Collections.Generic.List[string]'
        Mock Get-JunkMatch { $script:seen.Add($Item.Path); $null }
        Scan $script:H | Out-Null
        @($script:seen | Where-Object { $_.StartsWith($P + '\') }).Count | Should -Be 0
    }

    It 'a matched dir with an unreadable subdir is review with a suffix, not junk' -Skip:$script:NoChmod {
        Add-Project $script:H 'code/app'
        Add-File (Join-Path $script:H 'code/app/node_modules/a/locked/f') 0
        & chmod 000 (Join-Path $script:H 'code/app/node_modules/a/locked')
        $f = (Scan $script:H).Findings[0]
        $f.RuleId | Should -Be 'D5'
        $f.Tier | Should -Be 'review'
        $f.Reason | Should -BeLike '*; some contents could not be read'
    }

    It 'a symlink inside a matched dir makes it review (pnpm junction case)' {
        Add-Project $script:H 'code/app'
        New-Item -ItemType SymbolicLink -Path (Join-Path $script:H 'code/app/node_modules/lnk') -Target (Join-Path $script:H 'code') | Out-Null
        $f = (Scan $script:H).Findings[0]
        $f.Tier | Should -Be 'review'
        $f.Reason | Should -BeLike '*; some contents could not be read'
    }

    It 'a unaddressable name inside a matched dir makes it review' {
        Add-Project $script:H 'code/app'
        Add-File (Join-Path $script:H 'code/app/node_modules/a/nul.txt') 0
        (Scan $script:H).Findings[0].Tier | Should -Be 'review'
    }

    It 'a clean stale node_modules is still junk without the suffix' {
        Add-Project $script:H 'code/app'
        $f = (Scan $script:H).Findings[0]
        $f.Tier | Should -Be 'junk'
        $f.Reason | Should -Not -BeLike '*could not be read'
    }

    It 'outside ExtraRoot on a non-fixed drive is not walked and is recorded once' {
        $dl = Join-Path $TestDrive ('d' + [guid]::NewGuid().ToString('N'))
        Add-File (Join-Path $dl 'a.msi') 90
        $script:seen = New-Object 'System.Collections.Generic.List[string]'
        Mock Test-FixedDrive { $false }
        Mock Get-JunkMatch -MockWith { $script:seen.Add($Item.Path); $null }
        $r = Scan $script:H $dl
        @($r.Findings).Count | Should -Be 0
        @($script:seen | Where-Object { $_.StartsWith('Downloads\') }).Count | Should -Be 0
        @($r.Skipped).Count | Should -Be 1
        $r.Skipped[0].Path | Should -Be 'Downloads'
        $r.Skipped[0].Kind | Should -Be 'network or removable drive'
    }

    It 'outside ExtraRoot on a fixed drive is walked' {
        $dl = Join-Path $TestDrive ('d' + [guid]::NewGuid().ToString('N'))
        Add-File (Join-Path $dl 'a.msi') 90
        Mock Test-FixedDrive { $true }
        $r = Scan $script:H $dl
        @($r.Findings).Count | Should -Be 1
        @($r.Skipped).Count | Should -Be 0
    }

    It 'ExtraRoot is not descended below Downloads\sub' {
        $dl = Join-Path $TestDrive ('d' + [guid]::NewGuid().ToString('N'))
        Add-File (Join-Path $dl 'a/ok.msi') 90
        Add-File (Join-Path $dl 'a/b/c/x.msi') 90
        $script:seen = New-Object 'System.Collections.Generic.List[string]'
        Mock Get-JunkMatch -MockWith { $script:seen.Add($Item.Path); $null }
        Scan $script:H $dl | Out-Null
        $script:seen | Should -Contain 'Downloads\a\ok.msi'
        @($script:seen | Where-Object { $_.StartsWith('Downloads\a\b') }).Count | Should -Be 0
    }

    It 'chmod 000 dir is recorded as access denied and the scan continues' -Skip:$script:NoChmod {
        Add-Project $script:H 'code/app'
        Add-Dir (Join-Path $script:H 'locked/inner')
        & chmod 000 (Join-Path $script:H 'locked')
        $r = Scan $script:H
        @($r.Findings).Count | Should -Be 1
        @($r.Skipped).Count | Should -Be 1
        $r.Skipped[0].Path | Should -Be 'locked'
        $r.Skipped[0].Kind | Should -Be 'access denied'
    }

    It 'a locked dir inside a matched node_modules is recorded once, top-most' -Skip:$script:NoChmod {
        Add-Project $script:H 'code/app'
        Add-File (Join-Path $script:H 'code/app/node_modules/a/locked/inner/f') 60
        & chmod 000 (Join-Path $script:H 'code/app/node_modules/a/locked')
        $r = Scan $script:H
        @($r.Skipped).Count | Should -Be 1
        $r.Skipped[0].Path | Should -Be 'code\app\node_modules\a\locked'
    }

    It 'node_modules. next to a real one is unaddressable; only the real one is found' {
        Add-Project $script:H 'code/app'
        Add-File (Join-Path $script:H 'code/app/node_modules./x/i.js') 60
        $r = Scan $script:H
        @($r.Findings).Count | Should -Be 1
        $r.Findings[0].Path | Should -Be 'code\app\node_modules'
        @($r.Skipped).Count | Should -Be 1
        $r.Skipped[0].Path | Should -Be 'code\app\node_modules.'
        $r.Skipped[0].Kind | Should -Be 'unaddressable name'
    }

    It 'an unaddressable file inside a matched dir is not counted' {
        Add-Project $script:H 'code/app'
        Add-File (Join-Path $script:H 'code/app/node_modules/a/nul.txt') 60
        $r = Scan $script:H
        $r.Findings[0].Size | Should -Be 2
        $r.Skipped[0].Kind | Should -Be 'unaddressable name'
    }

    It 'an empty matched dir gives no finding' {
        Add-File (Join-Path $script:H 'code/app/package.json') 60
        Add-Dir (Join-Path $script:H 'code/app/node_modules/sub')
        @((Scan $script:H).Findings).Count | Should -Be 0
    }

    It 'a matched dir Modified equals its newest file' {
        Add-Project $script:H 'code/app'
        $newest = $script:Now.AddDays(-40); $newest = $newest.AddTicks(-($newest.Ticks % 10000000))
        $f = Join-Path $script:H 'code/app/node_modules/a/new.js'
        Add-File $f 0
        [IO.File]::SetLastWriteTimeUtc($f, $newest)
        $r = Scan $script:H
        $r.Findings[0].Modified.Ticks | Should -Be $newest.Ticks
        $r.Findings[0].RuleId | Should -Be 'D5'
    }

    It 'a fresh file inside makes node_modules review, not junk (age comes from contents)' {
        Add-Project $script:H 'code/app'
        Add-File (Join-Path $script:H 'code/app/node_modules/a/fresh.js') 1
        $r = Scan $script:H
        $r.Findings[0].Tier | Should -Be 'review'
    }

    It 'siblings come from the parent listing (target needs Cargo.toml)' {
        Add-File (Join-Path $script:H 'r1/Cargo.toml') 60
        Add-File (Join-Path $script:H 'r1/target/debug/x') 60
        Add-File (Join-Path $script:H 'r2/pom.xml') 60
        Add-File (Join-Path $script:H 'r2/target/classes/x') 60
        $r = Scan $script:H
        @($r.Findings).Count | Should -Be 1
        $r.Findings[0].RuleId | Should -Be 'D4'
    }

    It 'ExtraRoot is scanned for I1 only, with Downloads\ prefix' {
        $dl = Join-Path $TestDrive ('d' + [guid]::NewGuid().ToString('N'))
        Add-File (Join-Path $dl 'a.msi') 90
        Add-File (Join-Path $dl 'tool.exe') 90
        Add-Project $dl 'p'
        $r = Scan $script:H $dl
        @($r.Findings | ForEach-Object { $_.Path } | Sort-Object) | Should -Be @('Downloads\a.msi', 'Downloads\tool.exe')
        @($r.Findings | Where-Object { $_.Path -eq 'Downloads\a.msi' })[0].FullPath | Should -Be (Join-Path $dl 'a.msi')
    }

    It 'uses Get-DownloadsFolder when outside home, and ignores it when inside' {
        $dl = Join-Path $TestDrive ('d' + [guid]::NewGuid().ToString('N'))
        Add-File (Join-Path $dl 'a.msi') 90
        Mock Get-DownloadsFolder { $dl }
        @((Invoke-JunkScan -Root $script:H -Now $script:Now).Findings).Count | Should -Be 1
        Add-File (Join-Path $script:H 'Downloads/b.msi') 90
        Mock Get-DownloadsFolder { Join-Path $script:H 'Downloads' }
        $r = Invoke-JunkScan -Root $script:H -Now $script:Now
        @($r.Findings).Count | Should -Be 1
        $r.Findings[0].Path | Should -Be 'Downloads\b.msi'
    }
}
