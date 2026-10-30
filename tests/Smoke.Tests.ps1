BeforeAll {
    . (Join-Path (Join-Path $PSScriptRoot '..') 'junk.ps1')
}

Describe 'junk.ps1' {
    It 'loads Main without running it' {
        Get-Command Main -CommandType Function | Should -Not -BeNullOrEmpty
    }
}
