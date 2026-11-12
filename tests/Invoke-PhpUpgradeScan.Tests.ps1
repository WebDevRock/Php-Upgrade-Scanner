#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }
<#
    Pester 5+ tests for Invoke-PhpUpgradeScan.ps1

    Run from the repository root:
        Invoke-Pester .\tests
        Invoke-Pester .\tests -Output Detailed

    Fixtures:
        tests\fixtures\rules\   PHP files with known issues on known line numbers (copied to TestDrive per run)
        The .gitignore test repository is generated in TestDrive at run time, so the fixture's own
        .gitignore files can never affect the project's Git repository.
#>

BeforeDiscovery {
    $script:IsWindowsHost = [System.Environment]::OSVersion.Platform -eq 'Win32NT'
    $script:GitAvailable = [bool](Get-Command git -ErrorAction SilentlyContinue)
    $script:WinPowerShell = $null
    if ($script:IsWindowsHost) {
        $cmd = Get-Command powershell.exe -ErrorAction SilentlyContinue
        if ($cmd) { $script:WinPowerShell = $cmd.Source }
    }
}

BeforeAll {
    $script:ScanScript = Join-Path (Split-Path $PSScriptRoot -Parent) 'Invoke-PhpUpgradeScan.ps1'
    $script:FixtureSource = Join-Path $PSScriptRoot 'fixtures\rules'
    $script:HostExe = (Get-Process -Id $PID).Path

    # Runs the scanner in-process and returns the finding objects (-PassThru).
    function Invoke-Scan {
        param([Parameter(Mandatory = $true)][string]$Path, [hashtable]$Extra = @{})
        $out = Join-Path $TestDrive ('report-' + [guid]::NewGuid().ToString('N'))
        $params = @{ Path = $Path; Format = 'Csv'; OutputPath = $out; PassThru = $true }
        foreach ($k in $Extra.Keys) { $params[$k] = $Extra[$k] }
        @(& $script:ScanScript @params 6>$null 3>$null)
    }

    # Distinct relative file names (forward slashes) that produced at least one finding.
    function Get-FindingFiles($Findings) {
        @($Findings | ForEach-Object { $_.File -replace '\\', '/' } | Sort-Object -Unique)
    }

    function Find-Hit($Findings, [string]$File, [int]$Line, [string]$RuleId) {
        @($Findings | Where-Object { ($_.File -replace '\\', '/') -eq $File -and $_.Line -eq $Line -and $_.RuleId -eq $RuleId })
    }

    function New-PhpFile([string]$Path, [string]$Content = '<?php mysql_query("x");') {
        $dir = Split-Path $Path -Parent
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        [System.IO.File]::WriteAllText($Path, $Content)
    }
}

Describe 'Invoke-PhpUpgradeScan.ps1' {

    Context 'Script file' {
        It 'exists' {
            $script:ScanScript | Should -Exist
        }

        It 'parses without errors' {
            $errors = $null
            [System.Management.Automation.Language.Parser]::ParseFile($script:ScanScript, [ref]$null, [ref]$errors) | Out-Null
            $errors | Should -BeNullOrEmpty
        }

        It 'contains only ASCII characters (required for Windows PowerShell 5.1 without a BOM)' {
            $bytes = [System.IO.File]::ReadAllBytes($script:ScanScript)
            @($bytes | Where-Object { $_ -gt 127 }).Count | Should -Be 0
        }

        It 'compiles no code (no Add-Type -TypeDefinition / -MemberDefinition / -Path, no CodeDom)' {
            $tokens = $null; $errors = $null
            $ast = [System.Management.Automation.Language.Parser]::ParseFile($script:ScanScript, [ref]$tokens, [ref]$errors)
            $addType = $ast.FindAll({
                    param($n)
                    $n -is [System.Management.Automation.Language.CommandAst] -and $n.GetCommandName() -eq 'Add-Type'
                }, $true)
            foreach ($cmd in $addType) {
                # only loading an existing framework assembly by name is allowed (-Browse uses Windows Forms)
                $params = @($cmd.CommandElements | Where-Object { $_ -is [System.Management.Automation.Language.CommandParameterAst] } |
                        ForEach-Object { $_.ParameterName })
                $params | Should -Be @('AssemblyName')
            }
            $text = [System.IO.File]::ReadAllText($script:ScanScript)
            $text | Should -Not -Match 'CodeDom|CSharpCodeProvider|Microsoft\.CSharp'
        }

        It 'runs under Windows PowerShell 5.1' -Skip:(-not $script:WinPowerShell) {
            $dir = Join-Path $TestDrive 'ps51'
            New-PhpFile (Join-Path $dir 'a.php')
            $out = Join-Path $TestDrive 'ps51-report'
            $winPs = (Get-Command powershell.exe -ErrorAction Stop).Source   # discovery-time variables are not visible at run time
            & $winPs -NoProfile -ExecutionPolicy Bypass -File $script:ScanScript -Path $dir -Format Csv -OutputPath $out | Out-Null
            $LASTEXITCODE | Should -Be 0
            $rows = @(Import-Csv "$out.csv")
            $rows.Count | Should -Be 1
            $rows[0].RuleId | Should -Be 'FN-mysql_query'
        }
    }

    Context 'Rules (fixtures)' {
        BeforeAll {
            $script:RulesDir = Join-Path $TestDrive 'rules'
            Copy-Item -Path $script:FixtureSource -Destination $script:RulesDir -Recurse
            New-PhpFile (Join-Path $script:RulesDir 'vendor\x\bad.php') "<?php mysql_query('x');"
            $script:Findings = Invoke-Scan -Path $script:RulesDir
        }

        It 'reports <RuleId> (<Severity>) on legacy.php line <Line>' -ForEach @(
            @{ Line = 4;  RuleId = 'FN-mysql_connect';             Severity = 'Critical' }
            @{ Line = 5;  RuleId = 'FN-mysql_select_db';           Severity = 'Critical' }
            @{ Line = 7;  RuleId = 'FN-mysql_query';               Severity = 'Critical' }
            @{ Line = 7;  RuleId = 'DB-SQL-CONCAT';                Severity = 'High' }
            @{ Line = 8;  RuleId = 'FN-mysql_fetch_assoc';         Severity = 'Critical' }
            @{ Line = 9;  RuleId = 'DB-SQL-BUILD';                 Severity = 'Medium' }
            @{ Line = 11; RuleId = 'FN-ereg';                      Severity = 'Critical' }
            @{ Line = 11; RuleId = 'FN-split';                     Severity = 'Critical' }
            @{ Line = 12; RuleId = 'FN-create_function';           Severity = 'Critical' }
            @{ Line = 13; RuleId = 'LIST-EACH';                    Severity = 'Critical' }
            @{ Line = 14; RuleId = 'LIST-EMPTY';                   Severity = 'Critical' }
            @{ Line = 15; RuleId = 'LIST-APPEND-ORDER';            Severity = 'High' }
            @{ Line = 16; RuleId = 'LIST-SHORTFALL';               Severity = 'Medium' }
            @{ Line = 17; RuleId = 'LIST-STRING';                  Severity = 'High' }
            @{ Line = 19; RuleId = 'COUNT-VARIABLE';               Severity = 'Medium' }
            @{ Line = 21; RuleId = 'COUNT-SUPERGLOBAL';            Severity = 'High' }
            @{ Line = 22; RuleId = 'COUNT-FALSY-SOURCE';           Severity = 'High' }
            @{ Line = 23; RuleId = 'COUNT-SCALAR';                 Severity = 'Critical' }
            @{ Line = 24; RuleId = 'STRLEN-SUPERGLOBAL';           Severity = 'High' }
            @{ Line = 25; RuleId = 'STRLEN-EMPTY-TEST';            Severity = 'Low' }
            @{ Line = 26; RuleId = 'STRLEN-VARIABLE';              Severity = 'Low' }
            @{ Line = 28; RuleId = 'NULLARG-REQUEST';              Severity = 'Medium' }
            @{ Line = 29; RuleId = 'SYN-CURLY-OFFSET';             Severity = 'Critical' }
            @{ Line = 30; RuleId = 'SYN-REAL-CAST';                Severity = 'Critical' }
            @{ Line = 31; RuleId = 'SYN-NEW-BYREF';                Severity = 'Critical' }
            @{ Line = 32; RuleId = 'SYN-PREG-E';                   Severity = 'Critical' }
            @{ Line = 33; RuleId = 'SYN-PARSE-STR-1ARG';           Severity = 'Critical' }
            @{ Line = 34; RuleId = 'SYN-DEFINE-CI';                Severity = 'High' }
            @{ Line = 35; RuleId = 'SYN-IMPLODE-ORDER';            Severity = 'Critical' }
            @{ Line = 36; RuleId = 'SYN-DOLLAR-BRACE';             Severity = 'Medium' }
            @{ Line = 38; RuleId = 'SYN-NESTED-TERNARY';           Severity = 'High' }
            @{ Line = 40; RuleId = 'SYN-OPTIONAL-BEFORE-REQUIRED'; Severity = 'Medium' }
            @{ Line = 40; RuleId = 'SYN-IMPLICIT-NULLABLE';        Severity = 'Medium' }
            @{ Line = 42; RuleId = 'FN-utf8_encode';               Severity = 'Medium' }
            @{ Line = 43; RuleId = 'FN-strftime';                  Severity = 'Medium' }
            @{ Line = 44; RuleId = 'FN-mcrypt_encrypt';            Severity = 'Critical' }
            @{ Line = 45; RuleId = 'SYN-HTTP-VARS';                Severity = 'Critical' }
            @{ Line = 46; RuleId = 'CONST-MYSQL';                  Severity = 'Critical' }
            @{ Line = 47; RuleId = 'FN-get_magic_quotes_gpc';      Severity = 'Critical' }
            @{ Line = 50; RuleId = 'DB-ADDSLASHES';                Severity = 'Medium' }
            @{ Line = 51; RuleId = 'COMPAT-REGISTER-GLOBALS';      Severity = 'High' }
            @{ Line = 52; RuleId = 'COMPAT-VERSION-BRANCH';        Severity = 'Low' }
            @{ Line = 53; RuleId = 'COMPAT-SHIM-GUARD';            Severity = 'Medium' }
            @{ Line = 53; RuleId = 'COMPAT-INCLUDE';               Severity = 'Medium' }
            @{ Line = 54; RuleId = 'SYN-NONCANONICAL-CAST';        Severity = 'Low' }
            @{ Line = 55; RuleId = 'SYN-USER-ERROR';               Severity = 'Low' }
            @{ Line = 60; RuleId = 'SYN-RESERVED-CLASS';           Severity = 'Critical' }
            @{ Line = 62; RuleId = 'SYN-PHP4-CONSTRUCTOR';         Severity = 'Critical' }
            @{ Line = 66; RuleId = 'SYN-SHORT-OPEN-TAG';           Severity = 'Medium' }
        ) {
            $hit = @(Find-Hit $script:Findings 'legacy.php' $Line $RuleId)
            $hit.Count | Should -Be 1 -Because "legacy.php:$Line should trigger $RuleId"
            $hit[0].Severity | Should -Be $Severity
            $hit[0].SuggestedFix | Should -Not -BeNullOrEmpty
            $hit[0].PhpVersion | Should -Not -BeNullOrEmpty
        }

        It 'reports <RuleId> (<Severity>) on more-rules.php line <Line>' -ForEach @(
            @{ Line = 2;  RuleId = 'SYN-AUTOLOAD';             Severity = 'Critical' }
            @{ Line = 3;  RuleId = 'SYN-PHP-ERRORMSG';         Severity = 'Critical' }
            @{ Line = 4;  RuleId = 'SYN-RAW-POST-DATA';        Severity = 'Critical' }
            @{ Line = 5;  RuleId = 'SYN-ASSERT-STRING';        Severity = 'Critical' }
            @{ Line = 6;  RuleId = 'SYN-GLOBALS-WRITE';        Severity = 'Critical' }
            @{ Line = 7;  RuleId = 'SYN-CALLABLE-STRING';      Severity = 'Medium' }
            @{ Line = 8;  RuleId = 'SYN-GET-CLASS-NOARGS';     Severity = 'Low' }
            @{ Line = 9;  RuleId = 'CONST-FILTER-STRING';      Severity = 'Medium' }
            @{ Line = 10; RuleId = 'CONST-FILTER-FLAGS';       Severity = 'High' }
            @{ Line = 11; RuleId = 'CONST-INTL-IDNA-2003';     Severity = 'High' }
            @{ Line = 12; RuleId = 'CONST-MT-RAND-PHP';        Severity = 'Low' }
            @{ Line = 13; RuleId = 'CONST-E-STRICT';           Severity = 'Low' }
            @{ Line = 14; RuleId = 'VAR-HTTP-RESPONSE-HEADER'; Severity = 'Low' }
            @{ Line = 15; RuleId = 'PDO-DRIVER-CONSTANTS';     Severity = 'Low' }
            @{ Line = 16; RuleId = 'INI-REMOVED';              Severity = 'High' }
            @{ Line = 17; RuleId = 'DB-MANUAL-ESCAPE';         Severity = 'Low' }
            @{ Line = 18; RuleId = 'COMPAT-MYSQL2I';           Severity = 'High' }
            @{ Line = 19; RuleId = 'STRLEN-NULLABLE-SOURCE';   Severity = 'Medium' }
            @{ Line = 20; RuleId = 'LIST-MODERNISE';           Severity = 'Info' }
            @{ Line = 21; RuleId = 'FN-mhash';                 Severity = 'Medium' }
            @{ Line = 22; RuleId = 'FN-zip_open';              Severity = 'Medium' }
            @{ Line = 23; RuleId = 'FN-imap_open';             Severity = 'High' }
            @{ Line = 24; RuleId = 'FN-curl_close';            Severity = 'Low' }
            @{ Line = 27; RuleId = 'SYN-ASP-TAGS';             Severity = 'Medium' }
            @{ Line = 28; RuleId = 'SYN-SCRIPT-PHP';           Severity = 'Critical' }
        ) {
            $hit = @(Find-Hit $script:Findings 'more-rules.php' $Line $RuleId)
            $hit.Count | Should -Be 1 -Because "more-rules.php:$Line should trigger $RuleId"
            $hit[0].Severity | Should -Be $Severity
        }

        It 'reports <RuleId> on lib/mysql_shim.php line <Line>' -ForEach @(
            @{ Line = 2; RuleId = 'COMPAT-SHIM-GUARD' }
            @{ Line = 3; RuleId = 'COMPAT-SHIM-DEFINITION' }
            @{ Line = 5; RuleId = 'COMPAT-POLYFILL-GUARD' }
        ) {
            @(Find-Hit $script:Findings 'lib/mysql_shim.php' $Line $RuleId).Count | Should -Be 1
        }

        It 'reports <RuleId> for composer.json <Match>' -ForEach @(
            @{ RuleId = 'COMPOSER-PHP-CONSTRAINT'; Match = '^7.2';                    Severity = 'Medium' }
            @{ RuleId = 'COMPOSER-PLATFORM-PHP';   Match = '7.2.0';                   Severity = 'Medium' }
            @{ RuleId = 'COMPOSER-COMPAT-PACKAGE'; Match = 'dshafik/php7-mysql-shim'; Severity = 'High' }
            @{ RuleId = 'COMPOSER-COMPAT-PACKAGE'; Match = 'symfony/polyfill-php72';  Severity = 'Low' }
            @{ RuleId = 'COMPOSER-COMPAT-PACKAGE'; Match = 'paragonie/random_compat'; Severity = 'Low' }
        ) {
            $hit = @($script:Findings | Where-Object { $_.File -eq 'composer.json' -and $_.RuleId -eq $RuleId -and $_.Match -eq $Match })
            $hit.Count | Should -Be 1
            $hit[0].Severity | Should -Be $Severity
        }

        It 'ignores <Why> (legacy.php line <Line>)' -ForEach @(
            @{ Line = 1;  Why = 'the open tag' }
            @{ Line = 2;  Why = 'a // comment' }
            @{ Line = 3;  Why = 'a /* block */ comment' }
            @{ Line = 6;  Why = 'a plain superglobal read' }
            @{ Line = 10; Why = 'mysqli_query with a variable query' }
            @{ Line = 18; Why = 'short array destructuring' }
            @{ Line = 20; Why = 'count() guarded by is_array()' }
            @{ Line = 27; Why = 'strlen() guarded by ??' }
            @{ Line = 37; Why = 'single-quoted ${...}' }
            @{ Line = 39; Why = 'a parenthesised nested ternary' }
            @{ Line = 41; Why = 'an explicitly nullable parameter' }
            @{ Line = 48; Why = 'a ->each() method call' }
            @{ Line = 49; Why = 'a Foo::split() static call' }
            @{ Line = 56; Why = 'heredoc opener' }
            @{ Line = 57; Why = 'heredoc body containing function names' }
            @{ Line = 58; Why = 'heredoc closer' }
            @{ Line = 59; Why = 'a line marked phpscan:ignore' }
            @{ Line = 64; Why = 'inline HTML/JavaScript' }
        ) {
            @($script:Findings | Where-Object { $_.File -eq 'legacy.php' -and $_.Line -eq $Line }) | Should -BeNullOrEmpty
        }

        It 'does not add LIST-MODERNISE next to list() = each()' {
            Find-Hit $script:Findings 'legacy.php' 13 'LIST-MODERNISE' | Should -BeNullOrEmpty
        }

        It 'does not flag a constant SQL string (more-rules.php line 25)' {
            @($script:Findings | Where-Object { $_.File -eq 'more-rules.php' -and $_.Line -eq 25 }) | Should -BeNullOrEmpty
        }

        It 'does not flag a public each() method in a class' {
            @($script:Findings | Where-Object { $_.File -eq 'lib\mysql_shim.php' -and $_.Line -eq 8 }) | Should -BeNullOrEmpty
        }

        It 'reports nothing for modern PHP 8 code' {
            @($script:Findings | Where-Object { $_.File -eq 'modern.php' }) | Should -BeNullOrEmpty
        }

        It 'skips the vendor directory by default' {
            @($script:Findings | Where-Object { $_.File -like 'vendor*' }) | Should -BeNullOrEmpty
        }

        It 'scans vendor when -ExcludeDirectory is empty' {
            $all = Invoke-Scan -Path $script:RulesDir -Extra @{ ExcludeDirectory = @() }
            @(Find-Hit $all 'vendor/x/bad.php' 1 'FN-mysql_query').Count | Should -Be 1
        }

        It 'returns findings sorted by severity (most severe first)' {
            $rank = @{ Critical = 4; High = 3; Medium = 2; Low = 1; Info = 0 }
            $ranks = @($script:Findings | ForEach-Object { $rank[$_.Severity] })
            $sortedRanks = @($ranks | Sort-Object -Descending)
            ($ranks -join ',') | Should -Be ($sortedRanks -join ',')
        }
    }

    Context 'Options' {
        BeforeAll {
            $script:OptDir = Join-Path $TestDrive 'opts'
            Copy-Item -Path $script:FixtureSource -Destination $script:OptDir -Recurse
        }

        It '-TargetVersion 7.4 drops PHP 8 rules but keeps PHP 7 removals' {
            $f = Invoke-Scan -Path $script:OptDir -Extra @{ TargetVersion = '7.4' }
            @(Find-Hit $f 'legacy.php' 7 'FN-mysql_query').Count | Should -Be 1
            @(Find-Hit $f 'legacy.php' 44 'FN-mcrypt_encrypt').Count | Should -Be 1
            Find-Hit $f 'legacy.php' 12 'FN-create_function' | Should -BeNullOrEmpty
            Find-Hit $f 'legacy.php' 29 'SYN-CURLY-OFFSET' | Should -BeNullOrEmpty
            Find-Hit $f 'legacy.php' 42 'FN-utf8_encode' | Should -BeNullOrEmpty
            Find-Hit $f 'more-rules.php' 24 'FN-curl_close' | Should -BeNullOrEmpty
        }

        It '-MinSeverity High only returns High and Critical findings' {
            $f = Invoke-Scan -Path $script:OptDir -Extra @{ MinSeverity = 'High' }
            $f.Count | Should -BeGreaterThan 0
            @($f | Where-Object { $_.Severity -notin 'High', 'Critical' }) | Should -BeNullOrEmpty
        }

        It '-NoComposerCheck skips composer.json' {
            $f = Invoke-Scan -Path $script:OptDir -Extra @{ NoComposerCheck = $true }
            @($f | Where-Object { $_.RuleId -like 'COMPOSER-*' }) | Should -BeNullOrEmpty
        }

        It 'phpscan:ignore-file excludes a whole file' {
            $dir = Join-Path $TestDrive 'ignorefile'
            New-PhpFile (Join-Path $dir 'a.php') "<?php // phpscan:ignore-file`nmysql_query('x');"
            New-PhpFile (Join-Path $dir 'b.php') "<?php mysql_query('x');"
            Get-FindingFiles (Invoke-Scan -Path $dir) | Should -Be @('b.php')
        }

        It '-Extensions limits which files are scanned' {
            $dir = Join-Path $TestDrive 'ext'
            New-PhpFile (Join-Path $dir 'a.php')
            New-PhpFile (Join-Path $dir 'b.inc')
            Get-FindingFiles (Invoke-Scan -Path $dir -Extra @{ Extensions = @('.inc') }) | Should -Be @('b.inc')
        }

        It '-MaxFileSizeMB skips oversized files' {
            $dir = Join-Path $TestDrive 'big'
            New-PhpFile (Join-Path $dir 'big.php') ("<?php mysql_query('x');`n" + ('/' + '/' + ('x' * 100) + "`n") * 12000)
            New-PhpFile (Join-Path $dir 'small.php')
            Get-FindingFiles (Invoke-Scan -Path $dir -Extra @{ MaxFileSizeMB = 1 }) | Should -Be @('small.php')
        }
    }

    Context 'Reports and exit codes' {
        BeforeAll {
            $script:RepDir = Join-Path $TestDrive 'rep'
            Copy-Item -Path $script:FixtureSource -Destination $script:RepDir -Recurse
            $script:RepBase = Join-Path $TestDrive 'out\scan'
            New-Item -ItemType Directory -Path (Split-Path $script:RepBase) -Force | Out-Null
            $script:RepFindings = @(& $script:ScanScript -Path $script:RepDir -Format Both -OutputPath "$($script:RepBase).ignored-ext" -PassThru 6>$null 3>$null)
        }

        It 'writes CSV and HTML next to the -OutputPath base name' {
            "$($script:RepBase).csv" | Should -Exist
            "$($script:RepBase).html" | Should -Exist
        }

        It 'CSV has the documented columns and one row per finding' {
            $rows = @(Import-Csv "$($script:RepBase).csv")
            $rows.Count | Should -Be $script:RepFindings.Count
            $cols = $rows[0].PSObject.Properties.Name
            $cols | Should -Be @('Severity', 'Category', 'File', 'Line', 'Column', 'RuleId', 'Issue', 'PhpVersion', 'SuggestedFix', 'Match', 'Code')
        }

        It 'HTML has one table row per finding' {
            $html = [System.IO.File]::ReadAllText("$($script:RepBase).html")
            $html | Should -Match '<title>PHP Upgrade Scan</title>'
            ([regex]::Matches($html, '<tr data-sev=')).Count | Should -Be $script:RepFindings.Count
        }

        It 'writes a header-only CSV when there are no findings' {
            $dir = Join-Path $TestDrive 'clean'
            New-PhpFile (Join-Path $dir 'ok.php') '<?php echo "hello";'
            $base = Join-Path $TestDrive 'clean-report'
            & $script:ScanScript -Path $dir -Format Csv -OutputPath $base 6>$null 3>$null
            $lines = @(Get-Content "$base.csv")
            $lines.Count | Should -Be 1
            $lines[0] | Should -Match '^"Severity","Category","File"'
        }

        It '-OutputPath accepts an existing directory' {
            $dir = Join-Path $TestDrive 'outdir'
            New-Item -ItemType Directory -Path $dir | Out-Null
            & $script:ScanScript -Path $script:RepDir -Format Csv -OutputPath $dir 6>$null 3>$null
            @(Get-ChildItem $dir -Filter 'PHP-Upgrade-Report_*.csv').Count | Should -Be 1
        }

        It '-FailOn Critical exits with code 2 when Critical findings exist' {
            & $script:HostExe -NoProfile -ExecutionPolicy Bypass -File $script:ScanScript -Path $script:RepDir -Format Csv -OutputPath (Join-Path $TestDrive 'fail1') -FailOn Critical | Out-Null
            $LASTEXITCODE | Should -Be 2
        }

        It '-FailOn Critical exits with code 0 when there are none' {
            $dir = Join-Path $TestDrive 'failclean'
            New-PhpFile (Join-Path $dir 'ok.php') '<?php $x = strlen($y);'
            & $script:HostExe -NoProfile -ExecutionPolicy Bypass -File $script:ScanScript -Path $dir -Format Csv -OutputPath (Join-Path $TestDrive 'fail2') -FailOn Critical | Out-Null
            $LASTEXITCODE | Should -Be 0
        }
    }

    Context 'composer.json PHP constraint evaluation (target 8.5)' {
        It "constraint '<Constraint>' flagged = <Flagged>" -ForEach @(
            @{ Constraint = '^7.2';          Flagged = $true }
            @{ Constraint = '~7.4';          Flagged = $true }
            @{ Constraint = '7.4.*';         Flagged = $true }
            @{ Constraint = '>=7.2 <8.0';    Flagged = $true }
            @{ Constraint = '>=7.4';         Flagged = $false }
            @{ Constraint = '^8.0';          Flagged = $false }
            @{ Constraint = '^7.4 || ^8.1';  Flagged = $false }
            @{ Constraint = '8.5.*';         Flagged = $false }
            @{ Constraint = '~8.5.0';        Flagged = $false }
            @{ Constraint = '*';             Flagged = $false }
        ) {
            $dir = Join-Path $TestDrive ('composer-' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $dir | Out-Null
            $json = '{ "require": { "php": "' + $Constraint + '" } }'
            [System.IO.File]::WriteAllText((Join-Path $dir 'composer.json'), $json)
            $hit = @(Invoke-Scan -Path $dir | Where-Object RuleId -eq 'COMPOSER-PHP-CONSTRAINT')
            ($hit.Count -eq 1) | Should -Be $Flagged
        }
    }

    Context '.gitignore handling' {
        BeforeAll {
            $script:Repo = Join-Path $TestDrive 'gitrepo'
            New-Item -ItemType Directory -Path $script:Repo | Out-Null
            $script:RepoFiles = @(
                'app/index.php', 'app/Cache/a.php', 'cache/b.php', 'build/out.php', 'src/x.generated.php',
                'src/keep.generated.php', 'legacy-ignored.php', 'sub/legacy-ignored.php', 'docs/a/b/old.php',
                'docs/old.php', 'tmp1/t.php', 'tmpA/t.php', 'lib/mysql_shim.php', 'lib/other.php',
                'lib/deep/mysql_shim.php', 'logs/keep/k.php', 'logs/x.php', 'space dir/s.php',
                'storage/framework/views/v.php', 'storage/app/a.php', 'web/uploads/u.php', 'web/u.php'
            )
            foreach ($f in $script:RepoFiles) { New-PhpFile (Join-Path $script:Repo $f) }

            $gitignore = @(
                '# comment'
                'cache/'
                '/build'
                '*.generated.php'
                '!keep.generated.php'
                '/legacy-ignored.php'
                'docs/**/old.php'
                'tmp[0-9]/'
                'logs/*'
                '!logs/keep/'
                'storage/framework/'
                '**/uploads'
            ) -join "`n"
            [System.IO.File]::WriteAllText((Join-Path $script:Repo '.gitignore'), $gitignore + "`n")
            [System.IO.File]::WriteAllText((Join-Path $script:Repo 'lib\.gitignore'), "mysql_shim.php`n")

            $script:GitInit = $false
            if (Get-Command git -ErrorAction SilentlyContinue) {
                & git -C $script:Repo init -q 2>$null
                $script:GitInit = ($LASTEXITCODE -eq 0)
            }
            New-Item -ItemType Directory -Path (Join-Path $script:Repo '.git\info') -Force | Out-Null
            Add-Content -LiteralPath (Join-Path $script:Repo '.git\info\exclude') -Value 'space dir/'

            $script:DefaultScan = Invoke-Scan -Path $script:Repo
            $script:DefaultFiles = Get-FindingFiles $script:DefaultScan
        }

        It 'matches the file list from git ls-files --exclude-standard' -Skip:(-not $script:GitAvailable) {
            $script:GitInit | Should -BeTrue
            $expected = @(& git -C $script:Repo ls-files --cached --others --exclude-standard | Where-Object { $_ -like '*.php' } | Sort-Object)
            $expected.Count | Should -BeGreaterThan 0
            $script:DefaultFiles | Should -Be $expected
        }

        It '<File> is <State> (<Reason>)' -Skip:(-not $script:IsWindowsHost) -ForEach @(
            @{ File = 'app/index.php';                 State = 'scanned';  Reason = 'no rule' }
            @{ File = 'app/Cache/a.php';               State = 'excluded'; Reason = 'cache/ is case-insensitive on Windows' }
            @{ File = 'cache/b.php';                   State = 'excluded'; Reason = 'cache/' }
            @{ File = 'build/out.php';                 State = 'excluded'; Reason = '/build' }
            @{ File = 'src/x.generated.php';           State = 'excluded'; Reason = '*.generated.php' }
            @{ File = 'src/keep.generated.php';        State = 'scanned';  Reason = '!keep.generated.php' }
            @{ File = 'legacy-ignored.php';            State = 'excluded'; Reason = '/legacy-ignored.php (anchored)' }
            @{ File = 'sub/legacy-ignored.php';        State = 'scanned';  Reason = 'anchored pattern only matches at root' }
            @{ File = 'docs/a/b/old.php';              State = 'excluded'; Reason = 'docs/**/old.php' }
            @{ File = 'docs/old.php';                  State = 'excluded'; Reason = '** matches zero directories' }
            @{ File = 'tmp1/t.php';                    State = 'excluded'; Reason = 'tmp[0-9]/' }
            @{ File = 'tmpA/t.php';                    State = 'scanned';  Reason = 'outside [0-9]' }
            @{ File = 'lib/mysql_shim.php';            State = 'excluded'; Reason = 'nested lib/.gitignore' }
            @{ File = 'lib/deep/mysql_shim.php';       State = 'excluded'; Reason = 'nested .gitignore applies below it' }
            @{ File = 'lib/other.php';                 State = 'scanned';  Reason = 'no rule' }
            @{ File = 'logs/x.php';                    State = 'excluded'; Reason = 'logs/*' }
            @{ File = 'logs/keep/k.php';               State = 'scanned';  Reason = '!logs/keep/' }
            @{ File = 'space dir/s.php';               State = 'excluded'; Reason = '.git/info/exclude' }
            @{ File = 'storage/framework/views/v.php'; State = 'excluded'; Reason = 'storage/framework/' }
            @{ File = 'storage/app/a.php';             State = 'scanned';  Reason = 'sibling of excluded folder' }
            @{ File = 'web/uploads/u.php';             State = 'excluded'; Reason = '**/uploads' }
            @{ File = 'web/u.php';                     State = 'scanned';  Reason = 'no rule' }
        ) {
            ($script:DefaultFiles -contains $File) | Should -Be ($State -eq 'scanned')
        }

        It 'applies parent .gitignore files when scanning a subfolder (<Sub>)' -ForEach @(
            @{ Sub = 'docs'; Expected = @() }
            @{ Sub = 'logs'; Expected = @('keep/k.php') }
            @{ Sub = 'lib';  Expected = @('other.php') }
            @{ Sub = 'src';  Expected = @('keep.generated.php') }
        ) {
            $files = Get-FindingFiles (Invoke-Scan -Path (Join-Path $script:Repo $Sub))
            if ($Expected.Count -eq 0) { $files | Should -BeNullOrEmpty } else { $files | Should -Be $Expected }
        }

        It 'reports a .gitignore summary in the HTML header' {
            $base = Join-Path $TestDrive 'gi-html'
            & $script:ScanScript -Path $script:Repo -Format Html -OutputPath $base 6>$null 3>$null
            [System.IO.File]::ReadAllText("$base.html") | Should -Match '\.gitignore honoured: 13 pattern\(s\) from 3 ignore file\(s\)'
        }
    }

    Context '-NoGitIgnore' {
        BeforeAll {
            # Small repository: one kept file, one ignored file, one ignored folder.
            $script:NgRepo = Join-Path $TestDrive 'ng'
            New-PhpFile (Join-Path $script:NgRepo 'kept.php')
            New-PhpFile (Join-Path $script:NgRepo 'ignored.php')
            New-PhpFile (Join-Path $script:NgRepo 'cache\c.php')
            [System.IO.File]::WriteAllText((Join-Path $script:NgRepo '.gitignore'), "ignored.php`ncache/`n")
            New-Item -ItemType Directory -Path (Join-Path $script:NgRepo '.git') -Force | Out-Null
        }

        It 'honours .gitignore by default' {
            Get-FindingFiles (Invoke-Scan -Path $script:NgRepo) | Should -Be @('kept.php')
        }

        It '-NoGitIgnore scans ignored files and folders' {
            Get-FindingFiles (Invoke-Scan -Path $script:NgRepo -Extra @{ NoGitIgnore = $true }) | Should -Be @('cache/c.php', 'ignored.php', 'kept.php')
        }

        It '-NoGitIgnore omits the .gitignore summary from the HTML report' {
            $base = Join-Path $TestDrive 'ng-html'
            & $script:ScanScript -Path $script:NgRepo -Format Html -OutputPath $base -NoGitIgnore 6>$null 3>$null
            [System.IO.File]::ReadAllText("$base.html") | Should -Not -Match '\.gitignore honoured'
        }

        It 'legacy -UseGitIgnore still honours .gitignore' {
            Get-FindingFiles (Invoke-Scan -Path $script:NgRepo -Extra @{ UseGitIgnore = $true }) | Should -Be @('kept.php')
        }

        It '-UseGitIgnore with -NoGitIgnore warns and -NoGitIgnore wins' {
            $out = Join-Path $TestDrive 'ng-both'
            $w = $null
            $f = @(& $script:ScanScript -Path $script:NgRepo -Format Csv -OutputPath $out -PassThru -UseGitIgnore -NoGitIgnore -WarningVariable w -WarningAction SilentlyContinue 6>$null)
            (Get-FindingFiles $f).Count | Should -Be 3
            ($w | Out-String) | Should -Match 'NoGitIgnore wins'
        }

        It 'scans normally when no .gitignore exists' {
            $dir = Join-Path $TestDrive 'nogi'
            New-PhpFile (Join-Path $dir 'a.php')
            Get-FindingFiles (Invoke-Scan -Path $dir) | Should -Be @('a.php')
        }
    }
}
