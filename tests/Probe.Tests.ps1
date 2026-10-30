BeforeAll {
    . (Join-Path (Join-Path (Join-Path $PSScriptRoot '..') 'tools') 'probe.ps1')
}

Describe 'Format-ProbeLine' {
    It 'formats PASS with id, description and detail' {
        Format-ProbeLine -Status PASS -Id 'C1a' -Description 'exists' -Detail 'True' |
            Should -Be 'PASS C1a exists: True'
    }
    It 'formats FAIL and INFO' {
        Format-ProbeLine -Status FAIL -Id 'C2' -Description 'delete' -Detail 'IOException: x' | Should -Be 'FAIL C2 delete: IOException: x'
        Format-ProbeLine -Status INFO -Id 'C7' -Description 'path' -Detail 'missing' | Should -Be 'INFO C7 path: missing'
    }
    It 'keeps each result on exactly one line' {
        $l = Format-ProbeLine -Status FAIL -Id 'C1' -Description 'd' -Detail "a`r`nb`nc"
        $l | Should -Be 'FAIL C1 d: a b c'
    }
    It 'rejects unknown status' {
        { Format-ProbeLine -Status MAYBE -Id 'C1' -Description 'd' -Detail 'x' } | Should -Throw
    }
}
