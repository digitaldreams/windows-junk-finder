BeforeAll {
    . (Join-Path (Join-Path $PSScriptRoot '..') 'junk.ps1')
    $script:Now = [datetime]::new(2030, 1, 1, 0, 0, 0, [DateTimeKind]::Utc)
    function NewFinding($path, $cat, $tier, $size, $rule = 'X', $modDays = 10, $createdDays = $null, $reason = 'why') {
        $created = $script:Now.AddDays(-$modDays)
        if ($null -ne $createdDays) { $created = $script:Now.AddDays(-$createdDays) }
        [pscustomobject]@{ Path = $path; FullPath = "C:\Users\u\$path"; Kind = 'file'; Size = [long]$size
            Modified = $script:Now.AddDays(-$modDays); Created = $created
            Category = $cat; Tier = $tier; RuleId = $rule; Reason = $reason }
    }
    function NewReport($findings, $skipped = @()) { Format-JunkReport @{ Findings = @($findings); Skipped = @($skipped) } $script:Now }
    $script:Footer = @(
        'Notes'
        '- Sizes are logical (file lengths); NTFS compression, pnpm hard links and Dev Drive block clones can make totals overstate.'
        '- Skipped and built-in excluded areas are not scanned, so totals are a lower bound.'
        '- Not scanned by design: OneDrive, Documents, Desktop, Pictures, Music, Videos, app packages, credentials.'
        ''
    ) -join "`n"
}

Describe 'Format-JunkSize' {
    It '<b> -> <e>' -ForEach @(
        @{ b = 0; e = '0 B' }, @{ b = 999; e = '999 B' }, @{ b = 1000; e = '1 KB' }, @{ b = 12000; e = '12 KB' }
        @{ b = 999000; e = '999 KB' }, @{ b = 999499; e = '999 KB' }, @{ b = 999500; e = '1.0 MB' }
        @{ b = 1000000; e = '1.0 MB' }, @{ b = 1234567; e = '1.2 MB' }, @{ b = 340000000; e = '340 MB' }
        @{ b = 999000000; e = '999 MB' }, @{ b = 999500000; e = '1.0 GB' }, @{ b = 1000000000; e = '1.0 GB' }
        @{ b = 99949999; e = '99.9 MB' }, @{ b = 99950000; e = '100 MB' }, @{ b = 99950000000; e = '100 GB' }
        @{ b = 1200000000; e = '1.2 GB' }, @{ b = 2500000000000; e = '2.5 TB' }
    ) {
        Format-JunkSize ([long]$b) | Should -BeExactly $e
    }
}

Describe 'Format-JunkReport' {
    It 'renders a small report exactly' {
        $out = NewReport @(NewFinding 'AppData\Local\Temp\Big' 'Caches & logs' 'junk' 340000000 'C3' 214 $null 'temp file') @(
            [pscustomobject]@{ Path = 'locked'; Kind = 'access denied' })
        $expected = @(
            'Caches & logs'
            '    340 MB  junk    ~\AppData\Local\Temp\Big  (modified 214 d ago)  C3: temp file'
            ''
            'Junk (reclaimable): up to 340 MB'
            'Review (check before deleting): up to 0 B'
            ''
            'Skipped (not counted, sizes incomplete): 1 access denied (~\locked)'
            ''
        ) -join "`n"
        $out | Should -BeExactly ($expected + "`n" + $script:Footer)
    }

    It 'orders sections, sorts by size and totals per tier' {
        $out = NewReport @(
            (NewFinding 'big\a.bin' 'Big files' 'review' 700000000)
            (NewFinding 'Downloads\x.msi' 'Old installers' 'junk' 5000000)
            (NewFinding 'p\target' 'Dev junk' 'review' 1000000)
            (NewFinding 'p2\vendor' 'Dev junk' 'junk' 9000000)
            (NewFinding 'c\small' 'Caches & logs' 'junk' 1000)
            (NewFinding 'c\large' 'Caches & logs' 'junk' 2000))
        $lines = $out -split "`n"
        $idx = { param($s) [array]::IndexOf(@($lines | ForEach-Object { $_.Contains($s) }), $true) }
        $heads = 'Caches & logs', 'Dev junk', 'Old installers', 'Big files' | ForEach-Object { & $idx $_ }
        $heads | Should -Be ($heads | Sort-Object)
        (& $idx '~\c\large') | Should -BeLessThan (& $idx '~\c\small')
        (& $idx '~\p2\vendor') | Should -BeLessThan (& $idx '~\p\target')
        $out | Should -Match 'Junk \(reclaimable\): up to 14\.0 MB\n'
        $out | Should -Match 'Review \(check before deleting\): up to 701 MB\n'
    }

    It 'omits empty categories' {
        $out = NewReport @(NewFinding 'a' 'Big files' 'review' 600000000)
        $out | Should -Not -Match 'Dev junk'
        $out | Should -Match 'Big files'
    }

    It 'says so when nothing was found' {
        $out = NewReport @()
        $out | Should -Match 'No junk found\.'
        $out | Should -Match 'Skipped: none'
        $out | Should -Match 'Junk \(reclaimable\): up to 0 B'
    }

    It 'reports age from Modified, never negative' {
        (NewReport @(NewFinding 'a' 'Big files' 'review' 600000000 'B1' 40)) | Should -Match 'modified 40 d ago'
        (NewReport @(NewFinding 'a' 'Big files' 'review' 600000000 'B1' -5)) | Should -Match 'modified 0 d ago'
    }

    It 'groups the skipped line by kind and truncates names' {
        $s = @(
            'a', 'b', 'c', 'd' | ForEach-Object { [pscustomobject]@{ Path = $_; Kind = 'access denied' } }
            [pscustomobject]@{ Path = 'p'; Kind = 'path too long' }
            [pscustomobject]@{ Path = 'u'; Kind = 'unreadable' }
            [pscustomobject]@{ Path = 'o'; Kind = 'cloud-only' }
            [pscustomobject]@{ Path = 'n.'; Kind = 'unaddressable name' }
            [pscustomobject]@{ Path = 'Downloads'; Kind = 'network or removable drive' })
        $line = (NewReport @() $s) -split "`n" | Where-Object { $_.StartsWith('Skipped') }
        $line | Should -BeExactly ('Skipped (not counted, sizes incomplete): 4 access denied (~\a, ~\b, ~\c, ...); 1 path too long (~\p); ' +
            '1 unreadable (~\u); 1 cloud-only (~\o); 1 unaddressable name (~\n.); 1 network or removable drive (~\Downloads)')
    }

    It 'replaces control characters in finding and skipped paths' {
        $hostile = "evil`n$([char]27)[1Adir$([char]0x7F)x"
        $out = NewReport @(NewFinding $hostile 'Big files' 'review' 600000000) @([pscustomobject]@{ Path = $hostile; Kind = 'unreadable' })
        $out.Contains([string][char]27) | Should -BeFalse
        $out.Contains([string][char]0x7F) | Should -BeFalse
        $out | Should -Match ([regex]::Escape('~\evil??[1Adir?x'))
        @($out -split "`n" | Where-Object { $_.Contains('evil') }).Count | Should -Be 2
    }
}

Describe 'ConvertTo-SafeText' {
    It 'replaces C0, DEL, C1 and bidi overrides' {
        $in = "a`nb$([char]27)c$([char]0x9B)d$([char]0x202E)e$([char]0x2066)f$([char]0x2069)g$([char]0x7F)h`t"
        ConvertTo-SafeText $in | Should -BeExactly 'a?b?c?d?e?f?g?h?'
    }
    It 'keeps ordinary and non-ASCII text' {
        ConvertTo-SafeText "caf$([char]0xE9) \ dir-1" | Should -BeExactly "caf$([char]0xE9) \ dir-1"
    }
}

Describe 'Get-StartupBlock' {
    It 'passes in FullLanguage, not elevated' {
        Get-StartupBlock -LanguageMode 'FullLanguage' -Elevated $false | Should -BeNullOrEmpty
    }
    It 'blocks <m>' -ForEach @(@{ m = 'ConstrainedLanguage' }, @{ m = 'RestrictedLanguage' }, @{ m = 'NoLanguage' }) {
        Get-StartupBlock -LanguageMode $m -Elevated $false |
            Should -BeExactly 'Constrained Language Mode (App Control/AppLocker) blocks JunkFinder; run it on an unmanaged machine.'
    }
    It 'blocks an elevated shell' {
        Get-StartupBlock -LanguageMode 'FullLanguage' -Elevated $true |
            Should -BeExactly 'Run JunkFinder as a normal user, not as administrator.'
    }
    It 'reports the language mode first when both apply' {
        Get-StartupBlock -LanguageMode 'ConstrainedLanguage' -Elevated $true | Should -Match 'Constrained'
    }
}

Describe 'Source files' {
    It 'are pure ASCII (no BOM on disk, so 5.1 would read them as cp1252)' -ForEach @(
        @{ f = 'junk.ps1' }, @{ f = 'tools/probe.ps1' }) {
        $bytes = [IO.File]::ReadAllBytes((Join-Path (Join-Path $PSScriptRoot '..') $f))
        @($bytes | Where-Object { $_ -ge 0x80 }).Count | Should -Be 0
    }
}

Describe 'Report details' {
    It 'shows I1 age from the newer of Created and Modified, as added' {
        $f = NewFinding 'Downloads\x.msi' 'Old installers' 'junk' 1000000 'I1' 400 95
        (NewReport @($f)) | Should -Match 'added 95 d ago'
    }
    It 'keeps modified for other rules' {
        $f = NewFinding 'a' 'Big files' 'review' 600000000 'B1' 40 5
        (NewReport @($f)) | Should -Match 'modified 40 d ago'
    }
    It 'sanitizes rule id and reason' {
        $f = NewFinding 'a' 'Big files' 'review' 600000000 "B$([char]27)1" 40 $null "why$([char]0x202E)"
        $out = NewReport @($f)
        $out.Contains([string][char]27) | Should -BeFalse
        $out.Contains([string][char]0x202E) | Should -BeFalse
    }
}

Describe 'Main' {
    It 'exits 3 on a guard and prints nothing else' {
        Mock Test-Elevated { $true }
        Main -Arguments @() | Should -Be 3
    }
    It 'never asks about elevation outside FullLanguage' {
        Mock Test-Elevated { throw 'blocked under CLM' }
        Main -Arguments @() -LanguageMode 'ConstrainedLanguage' | Should -Be 3
        Should -Invoke Test-Elevated -Times 0
    }
    # Runs on every OS: a language-mode-restricted runspace behaves the same. $host.UI.WriteErrorLine is blocked under CLM
    # ("Method invocation is supported only on core types"), so the guard falls back to Write-Error there.
    It 'in a real Constrained Language Mode runspace the guard returns 3 and the message reaches the error stream' {
        $iss = [initialsessionstate]::CreateDefault()
        $iss.LanguageMode = 'ConstrainedLanguage'
        if ($env:OS -eq 'Windows_NT') { $iss.ExecutionPolicy = [Microsoft.PowerShell.ExecutionPolicy]::Bypass }
        $rs = [runspacefactory]::CreateRunspace($iss)
        $rs.Open()
        $ps = [powershell]::Create()
        try {
            $ps.Runspace = $rs
            $junk = [IO.Path]::GetFullPath((Join-Path (Join-Path $PSScriptRoot '..') 'junk.ps1'))
            [void]$ps.AddScript(". '$junk'; Main -Arguments @()")
            $out = @($ps.Invoke())
            $out.Count | Should -Be 1
            $out[0] | Should -Be 3
            @($ps.Streams.Error).Count | Should -Be 1
            $ps.Streams.Error[0].ToString() | Should -BeLike '*Constrained Language Mode*'
        }
        finally { $ps.Dispose(); $rs.Dispose() }
    }
    It 'clean without a section prints usage and exits 2 without scanning' {
        Mock Test-Elevated { $false }
        Mock Invoke-JunkScan { throw 'must not scan' }
        Main -Arguments @('clean') | Should -Be 2
        Main -Arguments @('clean', 'big') | Should -Be 2
    }
}
