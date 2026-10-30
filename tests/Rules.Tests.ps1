BeforeAll {
    . (Join-Path (Join-Path $PSScriptRoot '..') 'junk.ps1')
    $script:Now = New-Object DateTime 2026, 10, 30, 12, 0, 0, ([DateTimeKind]::Utc)
    function New-TestItem {
        param([string]$Path, [string]$Kind = 'file', [string[]]$Siblings = @(), [long]$Size = 1000,
              [double]$ModDays = 0, $CreatedDays = $null)
        if ($null -eq $CreatedDays) { $CreatedDays = $ModDays }
        [pscustomobject]@{
            Path = $Path; Kind = $Kind; Siblings = $Siblings; Size = $Size
            Modified = $script:Now.AddDays(-$ModDays); Created = $script:Now.AddDays(-$CreatedDays)
        }
    }
    function Get-M($item) { Get-JunkMatch -Item $item -Now $script:Now }
}

Describe 'Get-JunkMatch deny' {
    It 'pnpm store and nuget packages are never matched' -TestCases @(
        @{ P = 'AppData\Local\pnpm\store\v3\files\ab\x.msi' }
        @{ P = 'AppData\Local\pnpm\store' }
        @{ P = '.pnpm-store\v3\files\node_modules' }
        @{ P = '.nuget\packages\foo\1.0\lib\Cache' }
        @{ P = '.nuget\packages' }
    ) {
        Get-M (New-TestItem -Path $P -Kind dir -ModDays 400 -Size 900000000) | Should -BeNullOrEmpty
    }
}

Describe 'Get-JunkMatch deny (would match B1 otherwise)' {
    It 'blocks big old files inside the stores' -TestCases @(
        @{ P = '.pnpm-store\big.bin' }
        @{ P = 'AppData\Local\pnpm\x\big.bin' }
        @{ P = '.nuget\packages\big.bin' }
    ) {
        Get-M (New-TestItem -Path $P -Size 600000000 -ModDays 200) | Should -BeNullOrEmpty
    }
    It 'control: the same file elsewhere is B1' {
        (Get-M (New-TestItem -Path 'x\big.bin' -Size 600000000 -ModDays 200)).RuleId | Should -Be 'B1'
    }
}

Describe 'Edge cases' {
    It 'empty path component (trailing backslash) never matches' {
        Get-M (New-TestItem -Path 'AppData\Local\Temp\' -Kind dir -ModDays 30) | Should -BeNullOrEmpty
        Get-M (New-TestItem -Path 'AppData\Local\CrashDumps\' -ModDays 30) | Should -BeNullOrEmpty
    }
    It 'file name with quote does not throw and matches I1' {
        (Get-M (New-TestItem -Path 'Downloads\a"b.msi' -ModDays 40)).RuleId | Should -Be 'I1'
    }
    It 'leading-dot or dotless name has no extension' {
        Get-M (New-TestItem -Path 'Downloads\.msi' -ModDays 40) | Should -BeNullOrEmpty
        Get-M (New-TestItem -Path 'Downloads\msi' -ModDays 40) | Should -BeNullOrEmpty
    }
    It 'null Siblings does not throw' {
        $i = [pscustomobject]@{ Path = 'code\node_modules'; Kind = 'dir'; Siblings = $null; Size = 1; Modified = $script:Now; Created = $script:Now }
        { Get-M $i } | Should -Not -Throw
        Get-M $i | Should -BeNullOrEmpty
    }
    It 'exact boundaries are not matched / not junk' {
        Get-M (New-TestItem -Path 'AppData\Local\Microsoft\Windows\WER\ReportArchive\x' -Kind dir -ModDays 7) | Should -BeNullOrEmpty
        Get-M (New-TestItem -Path 'AppData\Local\Temp\x' -ModDays 7) | Should -BeNullOrEmpty
        (Get-M (New-TestItem -Path 'code\a\node_modules' -Kind dir -Siblings @('package.json', 'yarn.lock') -ModDays 30)).Tier | Should -Be 'review'
        Get-M (New-TestItem -Path 'Downloads\setup.msi' -ModDays 30) | Should -BeNullOrEmpty
    }
}

Describe 'C1 browser caches' {
    It 'matches Chromium cache dirs in any profile' -TestCases @(
        @{ P = 'AppData\Local\Google\Chrome\User Data\Default\Cache' }
        @{ P = 'AppData\Local\Google\Chrome\User Data\Profile 1\Code Cache' }
        @{ P = 'AppData\Local\Microsoft\Edge\User Data\Guest Profile\GPUCache' }
        @{ P = 'AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Media Cache' }
        @{ P = 'AppData\Local\Google\Chrome\User Data\ShaderCache' }
        @{ P = 'AppData\Local\Mozilla\Firefox\Profiles\abc.default\cache2' }
    ) {
        $m = Get-M (New-TestItem -Path $P -Kind dir)
        $m.RuleId | Should -Be 'C1'
        $m.Tier | Should -Be 'junk'
        $m.Category | Should -Be 'Caches & logs'
        $m.Reason | Should -Be 'browser cache; close the browser before deleting'
    }
    It 'does not match files inside the cache dir, other dirs, or files named Cache' -TestCases @(
        @{ P = 'AppData\Local\Google\Chrome\User Data\Default\Cache\f_000001'; K = 'file' }
        @{ P = 'AppData\Local\Google\Chrome\User Data\Default\Cache\sub'; K = 'dir' }
        @{ P = 'AppData\Local\Google\Chrome\User Data\Default\Cookies'; K = 'dir' }
        @{ P = 'AppData\Local\Google\Chrome\User Data\Default\Cache'; K = 'file' }
        @{ P = 'AppData\Local\Google\Chrome\User Data\Cache'; K = 'dir' }
        @{ P = 'AppData\Local\Mozilla\Firefox\Profiles\abc.default\storage'; K = 'dir' }
        @{ P = 'AppData\Local\Vivaldi\User Data\Default\Cache'; K = 'dir' }
    ) {
        Get-M (New-TestItem -Path $P -Kind $K) | Should -BeNullOrEmpty
    }
}

Describe 'C1e Electron caches' {
    It 'matches with GPUCache sibling' -TestCases @(
        @{ P = 'AppData\Roaming\Slack\Cache' }
        @{ P = 'AppData\Roaming\Slack\Code Cache' }
        @{ P = 'AppData\Roaming\Slack\GPUCache' }
    ) {
        $m = Get-M (New-TestItem -Path $P -Kind dir -Siblings @('GPUCache', 'Cache', 'Local Storage'))
        $m.RuleId | Should -Be 'C1e'
        $m.Tier | Should -Be 'junk'
        $m.Category | Should -Be 'Caches & logs'
        $m.Reason | Should -Be 'app cache; quit the app before deleting'
    }
    It 'does not match without a GPUCache sibling' {
        Get-M (New-TestItem -Path 'AppData\Roaming\Foo\Cache' -Kind dir -Siblings @('Cache', 'data')) | Should -BeNullOrEmpty
    }
    It 'does not match deeper or under Local' {
        Get-M (New-TestItem -Path 'AppData\Roaming\Slack\x\Cache' -Kind dir -Siblings @('GPUCache')) | Should -BeNullOrEmpty
        Get-M (New-TestItem -Path 'AppData\Local\Slack\Cache' -Kind dir -Siblings @('GPUCache')) | Should -BeNullOrEmpty
    }
}

Describe 'C2 crash reports' {
    It 'matches WER children and CrashDumps files older than 7 days' -TestCases @(
        @{ P = 'AppData\Local\Microsoft\Windows\WER\ReportArchive\Critical_x'; K = 'dir' }
        @{ P = 'AppData\Local\Microsoft\Windows\WER\ReportQueue\NonCritical_y'; K = 'dir' }
        @{ P = 'AppData\Local\CrashDumps\app.exe.123.dmp'; K = 'file' }
    ) {
        $m = Get-M (New-TestItem -Path $P -Kind $K -ModDays 8)
        $m.RuleId | Should -Be 'C2'
        $m.Tier | Should -Be 'junk'
        $m.Category | Should -Be 'Caches & logs'
        $m.Reason | Should -Be 'crash report older than 7 days'
    }
    It 'does not match at 6 days' -TestCases @(
        @{ P = 'AppData\Local\Microsoft\Windows\WER\ReportArchive\Critical_x'; K = 'dir' }
        @{ P = 'AppData\Local\CrashDumps\app.exe.123.dmp'; K = 'file' }
    ) {
        Get-M (New-TestItem -Path $P -Kind $K -ModDays 6) | Should -BeNullOrEmpty
    }
    It 'does not match the WER folder itself, deeper files, or CrashDumps subdirs' -TestCases @(
        @{ P = 'AppData\Local\Microsoft\Windows\WER\ReportArchive'; K = 'dir' }
        @{ P = 'AppData\Local\Microsoft\Windows\WER\ReportArchive\Critical_x\Report.wer'; K = 'file' }
        @{ P = 'AppData\Local\CrashDumps\sub'; K = 'dir' }
        @{ P = 'AppData\Local\Microsoft\Windows\WER\Temp\x'; K = 'dir' }
    ) {
        Get-M (New-TestItem -Path $P -Kind $K -ModDays 30) | Should -BeNullOrEmpty
    }
}

Describe 'C3 user temp' {
    It 'matches direct children older than 7 days' {
        $m = Get-M (New-TestItem -Path 'AppData\Local\Temp\foo.tmp' -ModDays 8)
        $m.RuleId | Should -Be 'C3'
        $m.Tier | Should -Be 'junk'
        $m.Category | Should -Be 'Caches & logs'
        $m.Reason | Should -Be 'temp file older than 7 days'
        (Get-M (New-TestItem -Path 'AppData\Local\Temp\sub' -Kind dir -ModDays 8)).RuleId | Should -Be 'C3'
    }
    It 'does not match at 6 days, Temp itself, or grandchildren' {
        Get-M (New-TestItem -Path 'AppData\Local\Temp\foo.tmp' -ModDays 6) | Should -BeNullOrEmpty
        Get-M (New-TestItem -Path 'AppData\Local\Temp' -Kind dir -ModDays 30) | Should -BeNullOrEmpty
        Get-M (New-TestItem -Path 'AppData\Local\Temp\sub\foo.tmp' -ModDays 30) | Should -BeNullOrEmpty
    }
}

Describe 'D3 package manager caches' {
    It 'matches the listed cache dirs' -TestCases @(
        @{ P = 'AppData\Local\npm-cache' }
        @{ P = 'AppData\Local\pip\Cache' }
        @{ P = 'AppData\Local\Yarn\Cache' }
        @{ P = 'AppData\Local\Composer' }
        @{ P = 'AppData\Local\NuGet\v3-cache' }
        @{ P = 'AppData\Local\go-build' }
        @{ P = '.cargo\registry\cache' }
    ) {
        $m = Get-M (New-TestItem -Path $P -Kind dir)
        $m.RuleId | Should -Be 'D3'
        $m.Tier | Should -Be 'junk'
        $m.Category | Should -Be 'Dev junk'
        $m.Reason | Should -Be 'package manager download cache; re-downloaded on demand'
    }
    It 'does not match siblings, children or look-alikes' -TestCases @(
        @{ P = 'AppData\Local\pip'; K = 'dir' }
        @{ P = 'AppData\Local\npm-cache\_cacache'; K = 'dir' }
        @{ P = '.cargo\registry'; K = 'dir' }
        @{ P = 'AppData\Local\npm-cache'; K = 'file' }
    ) {
        Get-M (New-TestItem -Path $P -Kind $K) | Should -BeNullOrEmpty
    }
    It 'wins over C3 precedence (D before C)' {
        (Get-M (New-TestItem -Path 'AppData\Local\npm-cache' -Kind dir -ModDays 30)).RuleId | Should -Be 'D3'
    }
}

Describe 'D4 Rust target' {
    It 'matches target next to Cargo.toml as review' {
        $m = Get-M (New-TestItem -Path 'code\app\target' -Kind dir -Siblings @('Cargo.toml', 'src'))
        $m.RuleId | Should -Be 'D4'
        $m.Tier | Should -Be 'review'
        $m.Category | Should -Be 'Dev junk'
        $m.Reason | Should -Be 'Rust build output next to Cargo.toml; rebuilt by cargo'
    }
    It 'does not match with only pom.xml, or for a file' {
        Get-M (New-TestItem -Path 'code\app\target' -Kind dir -Siblings @('pom.xml')) | Should -BeNullOrEmpty
        Get-M (New-TestItem -Path 'code\app\target' -Kind file -Siblings @('Cargo.toml')) | Should -BeNullOrEmpty
    }
}

Describe 'D5 node_modules' {
    It 'is junk when stale (31 d) with a lock file' -TestCases @(
        @{ L = 'package-lock.json' }, @{ L = 'yarn.lock' }, @{ L = 'pnpm-lock.yaml' }, @{ L = 'bun.lockb' }, @{ L = 'bun.lock' }
    ) {
        $m = Get-M (New-TestItem -Path 'code\app\node_modules' -Kind dir -Siblings @('package.json', $L) -ModDays 31)
        $m.RuleId | Should -Be 'D5'
        $m.Tier | Should -Be 'junk'
        $m.Category | Should -Be 'Dev junk'
        $m.Reason | Should -Be 'npm packages, unchanged for over 30 days; npm install restores them'
    }
    It 'is review at 29 d' {
        $m = Get-M (New-TestItem -Path 'code\app\node_modules' -Kind dir -Siblings @('package.json', 'yarn.lock') -ModDays 29)
        $m.Tier | Should -Be 'review'
        $m.Reason | Should -Be 'project build/dependency folder; restored by package manager'
    }
    It 'is review when stale but no lock file' {
        (Get-M (New-TestItem -Path 'code\app\node_modules' -Kind dir -Siblings @('package.json') -ModDays 90)).Tier | Should -Be 'review'
    }
    It 'does not match without package.json' {
        Get-M (New-TestItem -Path 'code\app\node_modules' -Kind dir -Siblings @('yarn.lock') -ModDays 90) | Should -BeNullOrEmpty
    }
    It 'matches case-insensitively' {
        (Get-M (New-TestItem -Path 'Code\App\NODE_MODULES' -Kind dir -Siblings @('PACKAGE.JSON', 'Yarn.Lock') -ModDays 31)).Tier | Should -Be 'junk'
    }
    It 'hidden-folder guard: dot folders and AppData never match' -TestCases @(
        @{ P = 'AppData\Local\Programs\x\resources\app\node_modules' }
        @{ P = 'appdata\roaming\x\node_modules' }
        @{ P = '.vscode\extensions\y\node_modules' }
    ) {
        Get-M (New-TestItem -Path $P -Kind dir -Siblings @('package.json', 'package-lock.json') -ModDays 90) | Should -BeNullOrEmpty
    }
    It 'beats B1 for a node_modules holding a 2 GB file (dir only, size irrelevant)' {
        (Get-M (New-TestItem -Path 'code\app\node_modules' -Kind dir -Siblings @('package.json') -Size 2000000000 -ModDays 400)).RuleId | Should -Be 'D5'
    }
}

Describe 'D6 vendor' {
    It 'is junk when stale (31 d) with composer.lock' {
        $m = Get-M (New-TestItem -Path 'code\site\vendor' -Kind dir -Siblings @('composer.json', 'composer.lock') -ModDays 31)
        $m.RuleId | Should -Be 'D6'
        $m.Tier | Should -Be 'junk'
        $m.Category | Should -Be 'Dev junk'
        $m.Reason | Should -Be 'Composer packages, unchanged for over 30 days; composer install restores them'
    }
    It 'is review at 29 d, or without composer.lock' {
        $a = Get-M (New-TestItem -Path 'code\site\vendor' -Kind dir -Siblings @('composer.json', 'composer.lock') -ModDays 29)
        $b = Get-M (New-TestItem -Path 'code\site\vendor' -Kind dir -Siblings @('composer.json') -ModDays 90)
        $a.Tier | Should -Be 'review'
        $b.Tier | Should -Be 'review'
        $a.Reason | Should -Be 'Composer packages; composer install restores them'
    }
    It 'does not match without composer.json, or under a hidden folder' {
        Get-M (New-TestItem -Path 'code\site\vendor' -Kind dir -Siblings @('composer.lock') -ModDays 90) | Should -BeNullOrEmpty
        Get-M (New-TestItem -Path 'AppData\Local\x\vendor' -Kind dir -Siblings @('composer.json', 'composer.lock') -ModDays 90) | Should -BeNullOrEmpty
        Get-M (New-TestItem -Path '.config\x\vendor' -Kind dir -Siblings @('composer.json', 'composer.lock') -ModDays 90) | Should -BeNullOrEmpty
    }
}

Describe 'I1 old installers' {
    It 'msi family is junk after 30 days' -TestCases @(
        @{ E = 'msi' }, @{ E = 'msix' }, @{ E = 'msixbundle' }, @{ E = 'appx' }, @{ E = 'appxbundle' }
    ) {
        $m = Get-M (New-TestItem -Path "Downloads\setup.$E" -ModDays 31)
        $m.RuleId | Should -Be 'I1'
        $m.Tier | Should -Be 'junk'
        $m.Category | Should -Be 'Old installers'
        $m.Reason | Should -Be 'installer added over 30 days ago'
    }
    It 'exe and iso are review' -TestCases @( @{ E = 'exe' }, @{ E = 'ISO' } ) {
        $m = Get-M (New-TestItem -Path "Downloads\setup.$E" -ModDays 31)
        $m.Tier | Should -Be 'review'
        $m.Reason | Should -Be "installer or disk image; make sure it isn't your only copy"
    }
    It 'does not match at 29 days' {
        Get-M (New-TestItem -Path 'Downloads\setup.msi' -ModDays 29) | Should -BeNullOrEmpty
    }
    It 'uses the newer of created and modified' {
        Get-M (New-TestItem -Path 'Downloads\setup.msi' -ModDays 400 -CreatedDays 2) | Should -BeNullOrEmpty
        (Get-M (New-TestItem -Path 'Downloads\setup.msi' -ModDays 2 -CreatedDays 400)) | Should -BeNullOrEmpty
        (Get-M (New-TestItem -Path 'Downloads\setup.msi' -ModDays 40 -CreatedDays 35)).RuleId | Should -Be 'I1'
    }
    It 'respects depth, kind and extension' {
        (Get-M (New-TestItem -Path 'Downloads\sub\setup.msi' -ModDays 40)).RuleId | Should -Be 'I1'
        Get-M (New-TestItem -Path 'Downloads\a\b\setup.msi' -ModDays 40) | Should -BeNullOrEmpty
        Get-M (New-TestItem -Path 'Downloads\setup.msi' -Kind dir -ModDays 40) | Should -BeNullOrEmpty
        Get-M (New-TestItem -Path 'Downloads\setup.zip' -ModDays 40) | Should -BeNullOrEmpty
        Get-M (New-TestItem -Path 'Other\setup.msi' -ModDays 40) | Should -BeNullOrEmpty
    }
    It 'matches case-insensitively on the folder' {
        (Get-M (New-TestItem -Path 'DOWNLOADS\Setup.MSI' -ModDays 40)).RuleId | Should -Be 'I1'
    }
}

Describe 'B1 big files' {
    It 'matches 500 MB, 181 d' {
        $m = Get-M (New-TestItem -Path 'Videos\big.bin' -Size 500000000 -ModDays 181)
        $m.RuleId | Should -Be 'B1'
        $m.Tier | Should -Be 'review'
        $m.Category | Should -Be 'Big files'
        $m.Reason | Should -Be 'large file (500 MB or more), not modified in over 180 days'
    }
    It 'does not match 499 MB, 179 d, or a dir' {
        Get-M (New-TestItem -Path 'x\big.bin' -Size 499999999 -ModDays 181) | Should -BeNullOrEmpty
        Get-M (New-TestItem -Path 'x\big.bin' -Size 500000000 -ModDays 179) | Should -BeNullOrEmpty
        Get-M (New-TestItem -Path 'x\big' -Kind dir -Size 500000000 -ModDays 181) | Should -BeNullOrEmpty
    }
    It 'is not used when an earlier rule matches' {
        (Get-M (New-TestItem -Path 'Downloads\big.iso' -Size 900000000 -ModDays 400)).RuleId | Should -Be 'I1'
    }
}

Describe 'Case' {
    It 'matches appdata\local\TEMP\x' {
        (Get-M (New-TestItem -Path 'appdata\local\TEMP\x' -ModDays 8)).RuleId | Should -Be 'C3'
    }
}
