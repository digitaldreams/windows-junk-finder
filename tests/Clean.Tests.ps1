BeforeAll {
    . (Join-Path (Join-Path $PSScriptRoot '..') 'junk.ps1')
    $script:Now = [DateTime]::UtcNow.AddDays(100)
    $script:Sep = [string][IO.Path]::DirectorySeparatorChar
    function Add-Dir($p) { New-Item -ItemType Directory -Force -Path $p | Out-Null }
    function Add-File($p, [double]$ModDays = 0) {
        Add-Dir (Split-Path $p -Parent)
        Set-Content -LiteralPath $p -Value 'x'
        [IO.File]::SetLastWriteTimeUtc($p, $script:Now.AddDays(-$ModDays))
    }
    # Finding for a fixture: Path uses '\', FullPath uses the real separator.
    function NewF($root, $rel, $rule = 'C3', $tier = 'junk', $kind = 'file', $size = 1000) {
        [pscustomobject]@{ Path = $rel; FullPath = ($root.TrimEnd('\', '/') + $script:Sep + $rel.Replace('\', $script:Sep)); Kind = $kind
            Size = [long]$size; Modified = $script:Now; Created = $script:Now
            Category = 'c'; Tier = $tier; RuleId = $rule; Reason = 'why' }
    }
    function NewPlanF($rel, $rule, $tier = 'junk') {
        [pscustomobject]@{ Path = $rel; FullPath = "C:\Users\u\$rel"; Kind = 'dir'; Size = [long]10; Tier = $tier; RuleId = $rule; Reason = 'why' }
    }
    function Opts($sections, $yes = $false, $perm = $false) { [pscustomobject]@{ Sections = $sections; Yes = $yes; Permanent = $perm } }
}

Describe 'ConvertFrom-CleanArgs' {
    It 'refuses no sections with usage' {
        $r = ConvertFrom-CleanArgs @()
        $r.Ok | Should -BeFalse
        $r.Message | Should -BeExactly 'Usage: junk clean <caches|logs|temp|dev|installers|node_modules|vendor>... [--yes] [--permanent]'
    }
    It 'refuses only flags' {
        (ConvertFrom-CleanArgs @('--yes')).Ok | Should -BeFalse
    }
    It 'refuses an unknown section and echoes it safely' {
        $r = ConvertFrom-CleanArgs @("bogus$([char]27)")
        $r.Ok | Should -BeFalse
        $r.Message | Should -BeLike "Unknown argument 'bogus?'.*Usage: junk clean*"
    }
    It 'refuses big' {
        $r = ConvertFrom-CleanArgs @('caches', 'big')
        $r.Ok | Should -BeFalse
        $r.Message | Should -BeExactly 'Big files are Review only; delete them by hand'
    }
    It 'parses flags in any order, with duplicates removed' {
        $r = ConvertFrom-CleanArgs @('--permanent', 'temp', '--yes', 'caches', 'temp')
        $r.Ok | Should -BeTrue
        @($r.Sections) | Should -Be @('temp', 'caches')
        $r.Yes | Should -BeTrue
        $r.Permanent | Should -BeTrue
    }
    It 'yes=<y> permanent=<p>' -TestCases @(
        @{ a = @('logs'); y = $false; p = $false }
        @{ a = @('logs', '--yes'); y = $true; p = $false }
        @{ a = @('--permanent', 'logs'); y = $false; p = $true }
        @{ a = @('--yes', '--permanent', 'logs'); y = $true; p = $true }
    ) {
        $r = ConvertFrom-CleanArgs $a
        $r.Yes | Should -Be $y
        $r.Permanent | Should -Be $p
    }
    It 'accepts every section' {
        (ConvertFrom-CleanArgs @('caches', 'logs', 'temp', 'dev', 'installers', 'node_modules', 'vendor')).Ok | Should -BeTrue
    }
}

Describe 'Get-CleanPlan' {
    It '<sec> selects exactly <rules>' -TestCases @(
        @{ sec = 'caches'; rules = @('C1', 'C1e') }, @{ sec = 'logs'; rules = @('C2') }, @{ sec = 'temp'; rules = @('C3') }
        @{ sec = 'dev'; rules = @('D3') }, @{ sec = 'installers'; rules = @('I1') }
        @{ sec = 'node_modules'; rules = @('D5') }, @{ sec = 'vendor'; rules = @('D6') }
    ) {
        $all = @('C1', 'C1e', 'C2', 'C3', 'D3', 'D4', 'D5', 'D6', 'I1', 'B1')
        $res = @{ Findings = @($all | ForEach-Object { NewPlanF "AppData\Roaming\X\$_" $_ }); Skipped = @() }
        $plan = Get-CleanPlan $res @($sec) @()
        @($plan.remove | ForEach-Object { $_.RuleId } | Sort-Object) | Should -Be @($rules | Sort-Object)
    }
    It 'never selects Review findings' {
        $res = @{ Findings = @(NewPlanF 'AppData\Local\Temp\a' 'C3' 'review', (NewPlanF 'Downloads\a.exe' 'I1' 'review')); Skipped = @() }
        $plan = Get-CleanPlan $res @('temp', 'installers') @()
        @($plan.remove).Count | Should -Be 0
        @($plan.skipped).Count | Should -Be 0
    }
    It 'skips C1 when its browser runs: <p> (<rel>)' -TestCases @(
        @{ p = 'chrome'; rel = 'AppData\Local\Google\Chrome\User Data\Default\Cache' }
        @{ p = 'BRAVE'; rel = 'AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Cache' }
        @{ p = 'firefox'; rel = 'AppData\Local\Mozilla\Firefox\Profiles\x.default\cache2' }
    ) {
        $res = @{ Findings = @(NewPlanF $rel 'C1'); Skipped = @() }
        $plan = Get-CleanPlan $res @('caches') @($p, 'explorer')
        @($plan.remove).Count | Should -Be 0
        $plan.skipped[0].reason | Should -BeExactly 'app running'
    }
    It 'removes C1 when another browser runs' {
        $res = @{ Findings = @(NewPlanF 'AppData\Local\Google\Chrome\User Data\Default\Cache' 'C1'); Skipped = @() }
        @((Get-CleanPlan $res @('caches') @('msedge', 'firefox')).remove).Count | Should -Be 1
    }
    It 'adds the Startup Boost hint for Edge' {
        $res = @{ Findings = @(NewPlanF 'AppData\Local\Microsoft\Edge\User Data\Default\Cache' 'C1'); Skipped = @() }
        $plan = Get-CleanPlan $res @('caches') @('msedge')
        $plan.skipped[0].reason | Should -BeExactly 'app running (Edge Startup Boost keeps it running; turn it off in edge://settings/system)'
    }
    It 'skips C1e when the app process runs, case-insensitively' {
        $res = @{ Findings = @((NewPlanF 'AppData\Roaming\Slack\Cache' 'C1e'), (NewPlanF 'AppData\Roaming\Discord\Cache' 'C1e')); Skipped = @() }
        $plan = Get-CleanPlan $res @('caches') @('slack')
        @($plan.remove | ForEach-Object { $_.Path }) | Should -Be @('AppData\Roaming\Discord\Cache')
        @($plan.skipped | ForEach-Object { $_.finding.Path }) | Should -Be @('AppData\Roaming\Slack\Cache')
    }
}

Describe 'Test-CleanTarget' {
    BeforeEach { $script:H = Join-Path $TestDrive ('h' + [guid]::NewGuid().ToString('N')); Add-Dir $script:H }
    It 'passes an untouched item' {
        Add-File "$script:H/AppData/Local/Temp/a.tmp"
        Test-CleanTarget (NewF $script:H 'AppData\Local\Temp\a.tmp') $script:H | Should -BeNullOrEmpty
    }
    It 'passes an untouched directory' {
        Add-File "$script:H/AppData/Local/npm-cache/x/y"
        Test-CleanTarget (NewF $script:H 'AppData\Local\npm-cache' 'D3' 'junk' 'dir') $script:H | Should -BeNullOrEmpty
    }
    It 'reports an item deleted before removal' {
        Add-Dir "$script:H/AppData/Local/Temp"
        Test-CleanTarget (NewF $script:H 'AppData\Local\Temp\gone.tmp') $script:H | Should -BeExactly 'no longer exists'
    }
    It 'reports a vanished parent' {
        Test-CleanTarget (NewF $script:H 'AppData\Local\Temp\gone.tmp') $script:H | Should -BeExactly 'parent no longer exists'
    }
    It 'rejects an item replaced by a symlink' {
        Add-File "$script:H/outside/target.txt"
        Add-Dir "$script:H/AppData/Local/Temp"
        New-Item -ItemType SymbolicLink -Path "$script:H/AppData/Local/Temp/a.tmp" -Target "$script:H/outside/target.txt" | Out-Null
        Test-CleanTarget (NewF $script:H 'AppData\Local\Temp\a.tmp') $script:H | Should -BeExactly 'is now a reparse point'
    }
    It 'rejects a parent swapped for a symlink to a directory outside the root' {
        $root = Join-Path $script:H 'root'
        Add-File "$script:H/elsewhere/a.tmp"
        Add-Dir "$root/AppData/Local"
        New-Item -ItemType SymbolicLink -Path "$root/AppData/Local/Temp" -Target "$script:H/elsewhere" | Out-Null
        Test-CleanTarget (NewF $root 'AppData\Local\Temp\a.tmp') $root | Should -BeExactly 'parent is now a reparse point'
    }
    It 'rejects a path outside the root' {
        Add-File "$script:H/a.tmp"
        $f = NewF $script:H 'a.tmp'
        Test-CleanTarget $f (Join-Path $script:H 'other') | Should -BeExactly 'path is not under the root'
    }
    It 'rejects dot components' {
        $f = NewF $script:H 'a\..\a.tmp'
        Test-CleanTarget $f $script:H | Should -BeExactly 'path is not under the root'
    }
    It 'rejects a name that is no longer addressable' {
        Add-File "$script:H/AppData/Local/Temp/x."
        Test-CleanTarget (NewF $script:H 'AppData\Local\Temp\x.') $script:H | Should -BeExactly 'unaddressable name'
    }
    It 'rejects a kind change' {
        Add-Dir "$script:H/AppData/Local/Temp/a.tmp"
        Test-CleanTarget (NewF $script:H 'AppData\Local\Temp\a.tmp') $script:H | Should -BeExactly 'is no longer a file'
    }
}

Describe 'Get-FindingRoot' {
    It 'uses home, the Downloads root, or nothing' {
        Mock Test-FixedDrive { $true }
        $f = [pscustomobject]@{ FullPath = 'C:\Users\u\a' }
        Get-FindingRoot $f 'C:\Users\u' 'D:\DL' | Should -BeExactly 'C:\Users\u'
        $d = [pscustomobject]@{ FullPath = 'D:\DL\a.msi' }
        Get-FindingRoot $d 'C:\Users\u' 'D:\DL' | Should -BeExactly 'D:\DL'
        Get-FindingRoot ([pscustomobject]@{ FullPath = 'E:\x' }) 'C:\Users\u' 'D:\DL' | Should -BeNullOrEmpty
        Get-FindingRoot ([pscustomobject]@{ FullPath = 'C:\Users\uu\a' }) 'C:\Users\u' '' | Should -BeNullOrEmpty
    }
    It 'refuses a Downloads root that is no longer a fixed drive' {
        Mock Test-FixedDrive { $false }
        Get-FindingRoot ([pscustomobject]@{ FullPath = 'D:\DL\a.msi' }) 'C:\Users\u' 'D:\DL' | Should -BeNullOrEmpty
    }
}

Describe 'Remove-JunkPermanent' {
    BeforeEach { $script:H = Join-Path $TestDrive ('p' + [guid]::NewGuid().ToString('N')); Add-Dir $script:H }
    It 'removes a tree that contains a ReadOnly file and directory' {
        Add-File "$script:H/t/a/b/ro.txt"
        Add-File "$script:H/t/c.txt"
        [IO.File]::SetAttributes("$script:H/t/a/b/ro.txt", [IO.FileAttributes]::ReadOnly)
        Remove-JunkPermanent "$script:H/t"
        Test-Path -LiteralPath "$script:H/t" | Should -BeFalse
    }
    It 'removes a symlink inside the tree and keeps its target' {
        Add-File "$script:H/keep/important.txt"
        Add-File "$script:H/t/a.txt"
        New-Item -ItemType SymbolicLink -Path "$script:H/t/link" -Target "$script:H/keep" | Out-Null
        New-Item -ItemType SymbolicLink -Path "$script:H/t/flink" -Target "$script:H/keep/important.txt" | Out-Null
        Remove-JunkPermanent "$script:H/t"
        Test-Path -LiteralPath "$script:H/t" | Should -BeFalse
        Test-Path -LiteralPath "$script:H/keep/important.txt" | Should -BeTrue
    }
    It 'removes a top-level symlink as a link only' {
        Add-File "$script:H/keep/important.txt"
        New-Item -ItemType SymbolicLink -Path "$script:H/link" -Target "$script:H/keep" | Out-Null
        Remove-JunkPermanent "$script:H/link"
        (Get-Item -LiteralPath "$script:H/link" -ErrorAction SilentlyContinue) | Should -BeNullOrEmpty
        Test-Path -LiteralPath "$script:H/keep/important.txt" | Should -BeTrue
    }
    It 'removes a single file' {
        Add-File "$script:H/f.txt"
        Remove-JunkPermanent "$script:H/f.txt"
        Test-Path -LiteralPath "$script:H/f.txt" | Should -BeFalse
    }
}

Describe 'Get-RecycleFlags' {
    It 'adds FOF_WANTNUKEWARNING unless --yes' {
        Get-RecycleFlags $false | Should -Be 0x4454
        Get-RecycleFlags $true | Should -Be 0x0454
    }
}

Describe 'Invoke-CleanItems' {
    BeforeEach { $script:H = Join-Path $TestDrive ('c' + [guid]::NewGuid().ToString('N')); Add-Dir $script:H }
    It 'recycles with the plain path and the interactive flags' {
        Add-File "$script:H/AppData/Local/Temp/a.tmp"
        Mock Invoke-Recycle { [pscustomobject]@{ Ok = $true; Code = 0 } }
        $f = NewF $script:H 'AppData\Local\Temp\a.tmp'
        $o = Invoke-CleanItems @($f) $script:H '' $false $false
        @($o.Removed).Count | Should -Be 1
        Should -Invoke Invoke-Recycle -Times 1 -Exactly -ParameterFilter { $Path -eq $f.FullPath -and $Flags -eq 0x4454 }
    }
    It 'passes the --yes flags' {
        Add-File "$script:H/AppData/Local/Temp/a.tmp"
        Mock Invoke-Recycle { [pscustomobject]@{ Ok = $true; Code = 0 } }
        Invoke-CleanItems @(NewF $script:H 'AppData\Local\Temp\a.tmp') $script:H '' $true $false | Out-Null
        Should -Invoke Invoke-Recycle -Times 1 -Exactly -ParameterFilter { $Flags -eq 0x0454 }
    }
    It 'reports a failed recycle with the code in hex and continues' {
        Add-File "$script:H/AppData/Local/Temp/a.tmp"
        Add-File "$script:H/AppData/Local/Temp/b.tmp"
        $script:n = 0
        Mock Invoke-Recycle { $script:n++; if ($script:n -eq 1) { [pscustomobject]@{ Ok = $false; Code = 0x7C } } else { [pscustomobject]@{ Ok = $true; Code = 0 } } }
        $o = Invoke-CleanItems @((NewF $script:H 'AppData\Local\Temp\a.tmp'), (NewF $script:H 'AppData\Local\Temp\b.tmp')) $script:H '' $false $false
        @($o.Failed).Count | Should -Be 1
        $o.Failed[0].reason | Should -BeLike '*0x7C*'
        @($o.Removed).Count | Should -Be 1
    }
    It 'reports a thrown error as failed and continues' {
        Add-File "$script:H/AppData/Local/Temp/a.tmp"
        Mock Invoke-Recycle { throw 'boom' }
        $o = Invoke-CleanItems @(NewF $script:H 'AppData\Local\Temp\a.tmp') $script:H '' $false $false
        @($o.Failed).Count | Should -Be 1
        $o.Failed[0].reason | Should -BeLike '*boom*'
    }
    It 'skips a vanished item without error and without calling the recycler' {
        Add-Dir "$script:H/AppData/Local/Temp"
        Mock Invoke-Recycle { throw 'must not run' }
        $o = Invoke-CleanItems @(NewF $script:H 'AppData\Local\Temp\gone.tmp') $script:H '' $false $false
        @($o.Skipped).Count | Should -Be 1
        @($o.Failed).Count | Should -Be 0
        $o.Skipped[0].reason | Should -BeExactly 'no longer exists'
    }
    It 'touches nothing outside the root when a parent became a symlink' {
        $root = Join-Path $script:H 'root'
        Add-File "$script:H/elsewhere/a.tmp"
        Add-Dir "$root/AppData/Local"
        New-Item -ItemType SymbolicLink -Path "$root/AppData/Local/Temp" -Target "$script:H/elsewhere" | Out-Null
        $o = Invoke-CleanItems @(NewF $root 'AppData\Local\Temp\a.tmp') $root '' $true $true
        @($o.Skipped).Count | Should -Be 1
        Test-Path -LiteralPath "$script:H/elsewhere/a.tmp" | Should -BeTrue
    }
    It 'never removes a Review finding' {
        Add-File "$script:H/AppData/Local/Temp/a.tmp"
        Mock Invoke-Recycle { throw 'must not run' }
        $o = Invoke-CleanItems @(NewF $script:H 'AppData\Local\Temp\a.tmp' 'C3' 'review') $script:H '' $false $false
        $o.Skipped[0].reason | Should -BeExactly 'not Junk tier'
    }
    It 'skips an item outside both roots' {
        $o = Invoke-CleanItems @([pscustomobject]@{ Path = 'x'; FullPath = '/nowhere/x'; Kind = 'file'; Size = 1; Tier = 'junk' }) $script:H '' $false $false
        $o.Skipped[0].reason | Should -BeExactly 'path is not under the root'
    }
    It 'permanent mode deletes without the recycler' {
        Add-File "$script:H/AppData/Local/Temp/a.tmp"
        Mock Invoke-Recycle { throw 'must not run' }
        $o = Invoke-CleanItems @(NewF $script:H 'AppData\Local\Temp\a.tmp') $script:H '' $true $true
        @($o.Removed).Count | Should -Be 1
        Test-Path -LiteralPath "$script:H/AppData/Local/Temp/a.tmp" | Should -BeFalse
    }
}

Describe 'Clean text' {
    It 'builds the prompts' {
        Get-CleanPrompt 3 2500000000 $false | Should -BeExactly 'Move 3 items (up to 2.5 GB) to the Recycle Bin? Items too large for it are deleted permanently. [y/N] '
        Get-CleanPrompt 3 2500000000 $true | Should -BeExactly 'Permanently delete 3 items (up to 2.5 GB)? This cannot be undone. [y/N] '
    }
    It 'confirms only y/yes' -TestCases @(
        @{ a = 'y'; e = $true }, @{ a = ' YES '; e = $true }, @{ a = 'Yes'; e = $true }
        @{ a = ''; e = $false }, @{ a = 'n'; e = $false }, @{ a = 'yep'; e = $false }, @{ a = $null; e = $false }
    ) {
        Test-CleanConfirmed $a | Should -Be $e
    }
    It 'renders the plan with safe paths, biggest first' {
        $a = [pscustomobject]@{ Path = 'small'; Size = [long]1000 }
        $b = [pscustomobject]@{ Path = "big$([char]27)"; Size = [long]5000000 }
        $s = [pscustomobject]@{ finding = [pscustomobject]@{ Path = 'run'; Size = 1 }; reason = 'app running' }
        $expected = @('To remove:', '    5.0 MB  ~\big?', '      1 KB  ~\small', 'Skipped:', '  ~\run  (skipped: app running)', 'Total: 2 items (up to 5.0 MB)') -join "`n"
        Format-CleanPlan @($a, $b) @($s) | Should -BeExactly $expected
    }
    It 'summarises recycle and permanent runs' {
        $o = @{ Removed = @([pscustomobject]@{ Size = [long]2000000 }); Skipped = @(1); Failed = @() }
        Get-CleanSummary $o 2 $false | Should -BeExactly "Moved 1 items (up to 2.0 MB) to the Recycle Bin; 3 skipped; 0 failed.`nSpace is freed when you empty the Recycle Bin."
        Get-CleanSummary $o 0 $true | Should -BeExactly 'Deleted 1 items (up to 2.0 MB); 1 skipped; 0 failed.'
    }
    It 'exits 1 only when something failed' {
        Get-CleanExitCode @{ Failed = @() } | Should -Be 0
        Get-CleanExitCode @{ Failed = @(1) } | Should -Be 1
    }
}

Describe 'Invoke-JunkClean' {
    BeforeEach {
        $script:H = Join-Path $TestDrive ('j' + [guid]::NewGuid().ToString('N'))
        Add-File "$script:H/AppData/Local/Temp/old.tmp" 30
        Mock Get-RunningProcessNames { @() }
        Mock Test-InputRedirected { $false }
        Mock Write-JunkLine { }
        Mock Invoke-Recycle { [pscustomobject]@{ Ok = $true; Code = 0 } }
    }
    It 'refuses without a terminal unless --yes, before scanning' {
        Mock Test-InputRedirected { $true }
        Mock Invoke-JunkScan { throw 'must not scan' }
        Invoke-JunkClean (Opts @('temp')) $script:H '' $script:Now | Should -Be 2
    }
    It 'prints Nothing to clean' {
        Remove-Item -LiteralPath "$script:H/AppData" -Recurse
        Invoke-JunkClean (Opts @('logs') $true) $script:H '' $script:Now | Should -Be 0
        Should -Invoke Write-JunkLine -ParameterFilter { $Text -eq 'Nothing to clean.' }
    }
    It 'aborts on anything but yes and removes nothing' {
        Mock Read-CleanAnswer { 'n' }
        Invoke-JunkClean (Opts @('temp')) $script:H '' $script:Now | Should -Be 0
        Should -Invoke Write-JunkLine -ParameterFilter { $Text -eq 'Aborted; nothing removed.' }
        Should -Invoke Invoke-Recycle -Times 0
    }
    It 'recycles after confirmation' {
        Mock Read-CleanAnswer { 'y' }
        Invoke-JunkClean (Opts @('temp')) $script:H '' $script:Now | Should -Be 0
        Should -Invoke Read-CleanAnswer -Times 1 -Exactly
        Should -Invoke Invoke-Recycle -Times 1 -Exactly
    }
    It '--yes does not prompt' {
        Mock Read-CleanAnswer { throw 'must not prompt' }
        Invoke-JunkClean (Opts @('temp') $true) $script:H '' $script:Now | Should -Be 0
        Should -Invoke Invoke-Recycle -Times 1 -Exactly
    }
    It 'returns 1 when an item fails' {
        Mock Invoke-Recycle { [pscustomobject]@{ Ok = $false; Code = 5 } }
        Invoke-JunkClean (Opts @('temp') $true) $script:H '' $script:Now | Should -Be 1
    }
    It '--permanent deletes for real inside the fixture' {
        Invoke-JunkClean (Opts @('temp') $true $true) $script:H '' $script:Now | Should -Be 0
        Test-Path -LiteralPath "$script:H/AppData/Local/Temp/old.tmp" | Should -BeFalse
        Should -Invoke Invoke-Recycle -Times 0
    }
}
