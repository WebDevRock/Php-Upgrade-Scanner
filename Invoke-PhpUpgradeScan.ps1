<#
.SYNOPSIS
    Scans PHP source code for removed / deprecated PHP features before a PHP upgrade.

.DESCRIPTION
    Recursively scans every PHP file below a directory (default: the current directory) and reports:

      * Removed and deprecated PHP functions (PHP 5.x through 8.5)
      * Removed / deprecated syntax (curly-brace offsets, (real) casts, /e modifier, ${} interpolation, ...)
      * Potentially unsafe count(), strlen() and list() usage (PHP 7/8 TypeErrors and null deprecations)
      * Legacy database APIs (mysql_*, mssql_*, sqlite_*, ...) and SQL built from variables
      * Compatibility-layer dependencies (mysql shims, polyfills, function_exists() guards, composer packages)

    Comments and inline HTML are ignored; string literals are ignored for rules that look at code only.
    A line can be excluded by adding the comment  phpscan:ignore  to it; a whole file can be excluded by
    adding  phpscan:ignore-file  anywhere in it.

    Compatible with Windows PowerShell 5.1 and PowerShell 7+.

.PARAMETER Path
    Directory to scan. Defaults to the current directory.

.PARAMETER Browse
    Show a folder picker to select the directory to scan.

.PARAMETER Format
    Report format: Html, Csv or Both (default).

.PARAMETER OutputPath
    Report file name (extension is replaced) or an existing directory. Defaults to
    .\PHP-Upgrade-Report_<timestamp>.html/.csv in the current directory.

.PARAMETER TargetVersion
    PHP version you are upgrading to (e.g. 7.4, 8.1, 8.4). Issues that only appear in later versions are skipped.
    Default: 8.5

.PARAMETER MinSeverity
    Lowest severity to report: Info, Low, Medium, High, Critical. Default: Info (everything).

.PARAMETER Extensions
    File extensions treated as PHP. Default: .php .php3 .php4 .php5 .php7 .phtml .inc

.PARAMETER ExcludeDirectory
    Directory names (wildcards allowed) that are not descended into.
    Default: vendor, node_modules, .git, .svn, .hg, .idea, .vscode   (pass @() to scan everything)

.PARAMETER NoGitIgnore
    Turn off .gitignore handling and scan files even if Git ignores them.

    By default .gitignore rules are honoured: files and folders ignored by Git are removed from the scan.
    Supports nested .gitignore files, .git/info/exclude, negation (!), anchored (/x), directory-only (x/)
    and ** patterns. If the scanned folder is inside a Git repository, .gitignore files between the
    repository root and the scanned folder are applied as well. Matching is case-insensitive (as Git on
    Windows). Git itself does not need to be installed. The global core.excludesFile is not read.

.PARAMETER MaxFileSizeMB
    Files larger than this are skipped. Default: 10

.PARAMETER NoComposerCheck
    Do not inspect composer.json files for compatibility packages and PHP constraints.

.PARAMETER FailOn
    Exit with code 2 if any finding is at or above this severity (useful in CI). Default: None.

.PARAMETER PassThru
    Write the finding objects to the pipeline.

.PARAMETER OpenReport
    Open the HTML report when the scan finishes.

.EXAMPLE
    .\Invoke-PhpUpgradeScan.ps1
    Scans the current directory for PHP 8.5 issues and writes HTML + CSV reports.

.EXAMPLE
    .\Invoke-PhpUpgradeScan.ps1 -Path C:\inetpub\wwwroot\site -TargetVersion 8.1 -Format Html -OpenReport

.EXAMPLE
    .\Invoke-PhpUpgradeScan.ps1 -Browse -MinSeverity High

.EXAMPLE
    .\Invoke-PhpUpgradeScan.ps1 -Path .\src -Format Csv -FailOn Critical

.EXAMPLE
    .\Invoke-PhpUpgradeScan.ps1 -NoGitIgnore
    Scans every PHP file, including those Git ignores (build output, caches, uploads...).
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Path = '.',

    [switch]$Browse,

    [ValidateSet('Html', 'Csv', 'Both')]
    [string]$Format = 'Both',

    [string]$OutputPath,

    [ValidatePattern('^\d+\.\d+$')]
    [string]$TargetVersion = '8.5',

    [ValidateSet('Info', 'Low', 'Medium', 'High', 'Critical')]
    [string]$MinSeverity = 'Info',

    [string[]]$Extensions = @('.php', '.php3', '.php4', '.php5', '.php7', '.phtml', '.inc'),

    [string[]]$ExcludeDirectory = @('vendor', 'node_modules', '.git', '.svn', '.hg', '.idea', '.vscode'),

    [switch]$NoGitIgnore,

    # Deprecated: .gitignore is now honoured by default. Accepted so older command lines keep working.
    [Parameter(DontShow = $true)]
    [switch]$UseGitIgnore,

    [ValidateRange(1, 1024)]
    [int]$MaxFileSizeMB = 10,

    [switch]$NoComposerCheck,

    [ValidateSet('None', 'Info', 'Low', 'Medium', 'High', 'Critical')]
    [string]$FailOn = 'None',

    [switch]$PassThru,

    [switch]$OpenReport
)

$scanStart = Get-Date
$target = [version]$TargetVersion

#region ---------------------------------------------------------------- Text helpers (PHP lexer-lite, pure PowerShell)
# No compiled C# (nothing is passed to the compiler): everything below is plain PowerShell plus .NET regex.
# Get-PhpStrippedText produces two copies of each file with identical length / line layout:
#   [0] "code" - comments and inline HTML blanked, string literals kept
#   [1] "bare" - as [0] but string contents blanked as well
#                (single-quoted / nowdoc -> spaces, double-quoted / heredoc / backtick -> \x01)
# The scanner jumps from token to token with regexes rather than walking every character,
# so it stays fast without compiled code.
$script:PhpInterp = [string][char]1
# PHP identifier character: ASCII letter / digit / underscore, or any char above 0x7F
$script:PhpIdentClass = '[^\x00-\x2F\x3A-\x40\x5B-\x5E\x60\x7B-\x7F]'
$script:reOpenTag = New-Object System.Text.RegularExpressions.Regex '<\?(?i:php)|<[?%]=?'
$script:rePhpToken = New-Object System.Text.RegularExpressions.Regex '\?>|%>|//|#(?!\[)|/\*|[''"`]|<<<'
$script:reLineEnd = New-Object System.Text.RegularExpressions.Regex '[\r\n]|\?>'
$script:reNotNewline = New-Object System.Text.RegularExpressions.Regex '[^\r\n]'
$script:reNewline = New-Object System.Text.RegularExpressions.Regex '\n'
$script:reHeredocStart = New-Object System.Text.RegularExpressions.Regex ('^<<<[ \t]*(?<q>[''"]?)(?<id>' + $script:PhpIdentClass + '+)')
$script:QuoteStop = @{
    [char]39 = [char[]]@([char]39, [char]92)    # '  or backslash
    [char]34 = [char[]]@([char]34, [char]92)    # "  or backslash
    [char]96 = [char[]]@([char]96, [char]92)    # `  or backslash
}

function Get-PhpStrippedText {
    param([string]$Src)
    # Each tokenising regex runs ONCE over the whole file and the loop below walks the match lists.
    # (Calling a .NET method with the whole file as an argument for every token is very slow on
    # PowerShell 7, whose per-call overhead grows with the argument size.)
    # Next match at or after $i = first listed match with Index >= $i, unless the previous listed
    # match straddles $i - then that list is out of step at $i and a fresh Match() from $i is used.
    $n = $Src.Length
    $code = New-Object System.Text.StringBuilder ($n + 1)
    $bare = New-Object System.Text.StringBuilder ($n + 1)
    $openMs = $script:reOpenTag.Matches($Src);  $openN = $openMs.Count; $openK = 0
    $tokMs = $script:rePhpToken.Matches($Src);  $tokN = $tokMs.Count;   $tokK = 0
    $endMs = $script:reLineEnd.Matches($Src);   $endN = $endMs.Count;   $endK = 0
    $i = 0
    while ($i -lt $n) {
        # ---- outside PHP: blank inline HTML up to the next open tag
        while ($openK -lt $openN -and $openMs[$openK].Index -lt $i) { $openK++ }
        $m = $null
        if ($openK -gt 0 -and ($openMs[$openK - 1].Index + $openMs[$openK - 1].Length) -gt $i) {
            $m = $script:reOpenTag.Match($Src, $i); if (-not $m.Success) { $m = $null }
        }
        elseif ($openK -lt $openN) { $m = $openMs[$openK] }
        if ($null -eq $m) {
            $t = $script:reNotNewline.Replace($Src.Substring($i), ' ')
            [void]$code.Append($t); [void]$bare.Append($t)
            break
        }
        if ($m.Index -gt $i) {
            $t = $script:reNotNewline.Replace($Src.Substring($i, $m.Index - $i), ' ')
            [void]$code.Append($t); [void]$bare.Append($t)
        }
        $tok = $m.Value
        [void]$code.Append($tok); [void]$bare.Append($tok)
        $asp = $tok[1] -eq [char]'%'
        $i = $m.Index + $m.Length

        # ---- inside PHP
        while ($i -lt $n) {
            while ($tokK -lt $tokN -and $tokMs[$tokK].Index -lt $i) { $tokK++ }
            $tm = $null
            if ($tokK -gt 0 -and ($tokMs[$tokK - 1].Index + $tokMs[$tokK - 1].Length) -gt $i) {
                $tm = $script:rePhpToken.Match($Src, $i); if (-not $tm.Success) { $tm = $null }
            }
            elseif ($tokK -lt $tokN) { $tm = $tokMs[$tokK] }
            if ($null -eq $tm) {
                $t = $Src.Substring($i)
                [void]$code.Append($t); [void]$bare.Append($t)
                $i = $n
                break
            }
            $p = $tm.Index
            if ($p -gt $i) { $t = $Src.Substring($i, $p - $i); [void]$code.Append($t); [void]$bare.Append($t) }
            $tok = $tm.Value

            if ($tok -eq '?>' -or ($tok -eq '%>' -and $asp)) {
                [void]$code.Append($tok); [void]$bare.Append($tok)
                $i = $p + 2
                break                                   # back to inline HTML
            }
            if ($tok -eq '%>') {                        # '%>' outside ASP tags is ordinary code
                [void]$code.Append('%'); [void]$bare.Append('%')
                $i = $p + 1
                continue
            }
            if ($tok -eq '//' -or $tok -eq '#') {       # line comment, ends at newline or ?>
                while ($endK -lt $endN -and $endMs[$endK].Index -lt $p) { $endK++ }
                $stop = $n
                if ($endK -gt 0 -and ($endMs[$endK - 1].Index + $endMs[$endK - 1].Length) -gt $p) {
                    $e = $script:reLineEnd.Match($Src, $p); if ($e.Success) { $stop = $e.Index }
                }
                elseif ($endK -lt $endN) { $stop = $endMs[$endK].Index }
                $t = ' ' * ($stop - $p)
                [void]$code.Append($t); [void]$bare.Append($t)
                $i = $stop
                continue
            }
            if ($tok -eq '/*') {                        # block comment
                $e = $Src.IndexOf('*/', $p + 2, [System.StringComparison]::Ordinal)
                if ($e -lt 0) { $stop = $n } else { $stop = $e + 2 }
                $t = $script:reNotNewline.Replace($Src.Substring($p, $stop - $p), ' ')
                [void]$code.Append($t); [void]$bare.Append($t)
                $i = $stop
                continue
            }
            if ($tok -eq '<<<') {                       # heredoc / nowdoc
                $win = [Math]::Min($n - $p, 1024)
                $hm = $script:reHeredocStart.Match($Src.Substring($p, $win))
                if ($hm.Success -and $hm.Length -eq $win -and $win -lt ($n - $p)) {
                    $hm = $script:reHeredocStart.Match($Src.Substring($p))      # identifier longer than the window
                }
                if (-not $hm.Success) {
                    [void]$code.Append('<'); [void]$bare.Append('<')
                    $i = $p + 1
                    continue
                }
                $id = $hm.Groups['id'].Value
                if ($hm.Groups['q'].Value -eq "'") { $fill = ' ' } else { $fill = $script:PhpInterp }
                $nl = $Src.IndexOf([char]10, $p + $hm.Length)
                if ($nl -lt 0) {
                    $t = $Src.Substring($p)
                    [void]$code.Append($t); [void]$bare.Append($t)
                    $i = $n
                    continue
                }
                $bodyStart = $nl + 1
                $reEnd = New-Object System.Text.RegularExpressions.Regex ('(?m)^[ \t]*' + [regex]::Escape($id) + '(?!' + $script:PhpIdentClass + ')')
                $em = $reEnd.Match($Src, $bodyStart)
                if ($em.Success) { $bodyEnd = $em.Index } else { $bodyEnd = $n }
                [void]$code.Append($Src.Substring($p, $bodyEnd - $p))
                [void]$bare.Append($Src.Substring($p, $bodyStart - $p))
                [void]$bare.Append($script:reNotNewline.Replace($Src.Substring($bodyStart, $bodyEnd - $bodyStart), $fill))
                $i = $bodyEnd
                continue
            }
            # quoted string: ' " or ` - a backslash escapes the next character
            $q = $tok[0]
            if ($q -eq [char]39) { $fill = ' ' } else { $fill = $script:PhpInterp }
            $stopChars = $script:QuoteStop[$q]
            $e = $p + 1
            $closed = $false
            while ($true) {
                $e = $Src.IndexOfAny($stopChars, $e)
                if ($e -lt 0) { $e = $n; break }
                if ($Src[$e] -eq [char]92) {
                    if ($e + 1 -lt $n) { $e += 2; continue }
                    $e = $n; break                      # lone trailing backslash: unterminated
                }
                $closed = $true; break
            }
            if ($closed) { $next = $e + 1 } else { $next = $n }
            [void]$code.Append($Src.Substring($p, $next - $p))
            [void]$bare.Append($q)
            [void]$bare.Append($script:reNotNewline.Replace($Src.Substring($p + 1, $e - $p - 1), $fill))
            if ($closed) { [void]$bare.Append($q) }
            $i = $next
        }
    }
    , @($code.ToString(), $bare.ToString())
}

function Get-LineStarts {
    # Offsets at which each line starts (line N starts at element N-1)
    param([string]$Text)
    $ms = $script:reNewline.Matches($Text)
    $starts = New-Object int[] ($ms.Count + 1)
    for ($k = 0; $k -lt $ms.Count; $k++) { $starts[$k + 1] = $ms[$k].Index + 1 }
    , $starts
}

function Get-LineNumber {
    # 1-based line number containing character offset $Pos
    param([int[]]$Starts, [int]$Pos)
    $r = [Array]::BinarySearch($Starts, $Pos)
    if ($r -ge 0) { $r + 1 } else { -bnot $r }
}

function Get-LineText {
    param([string]$Text, [int[]]$Starts, [int]$Line)
    $a = $Starts[$Line - 1]
    if ($Line -lt $Starts.Length) { $b = $Starts[$Line] } else { $b = $Text.Length }
    $Text.Substring($a, $b - $a).TrimEnd([char]13, [char]10)
}
#endregion

#region ---------------------------------------------------------------- .gitignore matcher (pure PowerShell)
# Native .gitignore evaluator (no git.exe required). The matcher is a hashtable:
#   Root, Rules (base folder -> rule list), LoadedDirs, LoadedFiles, PatternCount
# Matching is case-insensitive (like Git on Windows); the last matching rule wins, and rules in
# deeper .gitignore files are evaluated after (and so override) shallower ones.
function New-GitIgnoreState {
    param([string]$RootPath)
    @{
        Root         = [System.IO.Path]::GetFullPath($RootPath).TrimEnd('\', '/')
        Rules        = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
        LoadedDirs   = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        LoadedFiles  = New-Object System.Collections.Generic.List[string]
        PatternCount = 0
    }
}

function Get-GitIgnoreRelPath {
    param($Matcher, [string]$FullPath)
    $full = [System.IO.Path]::GetFullPath($FullPath).TrimEnd('\', '/')
    if ($full.Length -le $Matcher.Root.Length) { return '' }
    $full.Substring($Matcher.Root.Length + 1).Replace('\', '/')
}

function ConvertFrom-GitIgnoreGlob {
    param([string]$Glob)
    $sb = New-Object System.Text.StringBuilder
    $n = $Glob.Length
    $i = 0
    while ($i -lt $n) {
        $c = $Glob[$i]
        if ($c -eq [char]'*' -and $i + 1 -lt $n -and $Glob[$i + 1] -eq [char]'*' -and ($i -eq 0 -or $Glob[$i - 1] -eq [char]'/')) {
            if ($i + 2 -eq $n) { [void]$sb.Append('.*'); $i += 2; continue }
            if ($Glob[$i + 2] -eq [char]'/') { [void]$sb.Append('(?:.*/)?'); $i += 3; continue }
        }
        if ($c -eq [char]'*') {
            while ($i -lt $n -and $Glob[$i] -eq [char]'*') { $i++ }
            [void]$sb.Append('[^/]*')
            continue
        }
        if ($c -eq [char]'?') { [void]$sb.Append('[^/]'); $i++; continue }
        if ($c -eq [char]'\' -and $i + 1 -lt $n) { [void]$sb.Append([regex]::Escape([string]$Glob[$i + 1])); $i += 2; continue }
        if ($c -eq [char]'[') {
            $j = $i + 1
            if ($j -lt $n -and ($Glob[$j] -eq [char]'!' -or $Glob[$j] -eq [char]'^')) { $j++ }
            if ($j -lt $n -and $Glob[$j] -eq [char]']') { $j++ }
            while ($j -lt $n -and $Glob[$j] -ne [char]']') { $j++ }
            if ($j -lt $n) {
                $inner = $Glob.Substring($i + 1, $j - $i - 1)
                $negate = $inner.Length -gt 0 -and ($inner[0] -eq [char]'!' -or $inner[0] -eq [char]'^')
                if ($negate) { $inner = $inner.Substring(1) }
                $inner = $inner.Replace('\', '\\').Replace('[', '\[')
                if ($negate) { [void]$sb.Append('[^/') } else { [void]$sb.Append('[') }
                [void]$sb.Append($inner).Append(']')
                $i = $j + 1
                continue
            }
        }
        [void]$sb.Append([regex]::Escape([string]$c))
        $i++
    }
    $sb.ToString()
}

function Import-GitIgnoreFile {
    # Loads a pattern file whose patterns are relative to the folder $BaseRel (repository-relative)
    param($Matcher, [string]$File, [string]$BaseRel)
    try { $lines = [System.IO.File]::ReadAllLines($File) } catch { return }
    if (-not $Matcher.Rules.ContainsKey($BaseRel)) { $Matcher.Rules[$BaseRel] = New-Object System.Collections.Generic.List[object] }
    $list = $Matcher.Rules[$BaseRel]
    $opts = [System.Text.RegularExpressions.RegexOptions]::IgnoreCase -bor [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    $added = 0
    foreach ($rawLine in $lines) {
        $line = $rawLine.TrimEnd([char]13)
        if ($line.Length -eq 0 -or $line[0] -eq [char]'#') { continue }
        $end = $line.Length
        while ($end -gt 0 -and ($line[$end - 1] -eq [char]' ' -or $line[$end - 1] -eq [char]9) -and -not ($end -ge 2 -and $line[$end - 2] -eq [char]'\')) { $end-- }
        $line = $line.Substring(0, $end)
        if ($line.Length -eq 0) { continue }

        $neg = $false
        if ($line[0] -eq [char]'!') { $neg = $true; $line = $line.Substring(1) }
        elseif ($line.StartsWith('\!') -or $line.StartsWith('\#')) { $line = $line.Substring(1) }

        $dirOnly = $false
        if ($line.EndsWith('/')) { $dirOnly = $true; $line = $line.TrimEnd('/') }
        if ($line.Length -eq 0) { continue }

        $anchored = $line.IndexOf('/') -ge 0
        if ($line[0] -eq [char]'/') { $line = $line.Substring(1) }
        if ($line.Length -eq 0) { continue }

        $body = ConvertFrom-GitIgnoreGlob $line
        if ($anchored) { $pattern = '^' + $body + '$' } else { $pattern = '^(?:.*/)?' + $body + '$' }
        try { $re = New-Object System.Text.RegularExpressions.Regex($pattern, $opts) } catch { continue }
        $list.Add([pscustomobject]@{ Re = $re; Negate = $neg; DirOnly = $dirOnly })
        $added++
    }
    $Matcher.PatternCount += $added
    $Matcher.LoadedFiles.Add($File)
}

function Add-GitIgnoreDirectory {
    # Loads <dir>/.gitignore (once per directory)
    param($Matcher, [string]$Dir)
    $rel = Get-GitIgnoreRelPath $Matcher $Dir
    if (-not $Matcher.LoadedDirs.Add($rel)) { return }
    $f = [System.IO.Path]::Combine($Dir, '.gitignore')
    if ([System.IO.File]::Exists($f)) { Import-GitIgnoreFile $Matcher $f $rel }
}

function Add-GitIgnoreFileFor {
    # Loads a pattern file whose patterns are relative to $BaseDir (e.g. .git/info/exclude -> repo root)
    param($Matcher, [string]$File, [string]$BaseDir)
    if ([System.IO.File]::Exists($File)) { Import-GitIgnoreFile $Matcher $File (Get-GitIgnoreRelPath $Matcher $BaseDir) }
}

function Test-GitIgnored {
    param($Matcher, [string]$FullPath, [bool]$IsDirectory)
    $rel = Get-GitIgnoreRelPath $Matcher $FullPath
    if ($rel.Length -eq 0) { return $false }
    $ignored = $false
    $baseRel = ''
    $idx = -1
    while ($true) {
        if ($Matcher.Rules.ContainsKey($baseRel)) {
            if ($baseRel.Length -eq 0) { $sub = $rel } else { $sub = $rel.Substring($baseRel.Length + 1) }
            foreach ($r in $Matcher.Rules[$baseRel]) {
                if ($r.DirOnly -and -not $IsDirectory) { continue }
                if ($r.Re.IsMatch($sub)) { $ignored = -not $r.Negate }
            }
        }
        $idx = $rel.IndexOf('/', $idx + 1)
        if ($idx -lt 0) { break }
        $baseRel = $rel.Substring(0, $idx)
    }
    $ignored
}
#endregion

#region ---------------------------------------------------------------- Rule infrastructure
$SeverityRank = @{ Info = 0; Low = 1; Medium = 2; High = 3; Critical = 4 }
$minRank = $SeverityRank[$MinSeverity]

$Rules = New-Object System.Collections.Generic.List[object]
$baseOptions = [System.Text.RegularExpressions.RegexOptions]::Compiled -bor [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
$ciOptions = $baseOptions -bor [System.Text.RegularExpressions.RegexOptions]::IgnoreCase

function Test-VersionInScope([string]$Version) {
    if ([string]::IsNullOrEmpty($Version)) { return $true }
    return ([version]$Version -le $target)
}

function Get-StatusText([string]$Status, [string]$Version) {
    switch ($Status) {
        'Removed'         { $t = 'Removed in PHP' }
        'Deprecated'      { $t = 'Deprecated in PHP' }
        'Unbundled'       { $t = 'Moved to PECL in PHP' }
        'BehaviourChange' { $t = 'Behaviour changed in PHP' }
        'Modernise'       { $t = 'Modernise (PHP' }
        'Risk'            { return 'Security / reliability risk' }
        'Compat'          { return 'Compatibility layer' }
        default           { $t = $Status }
    }
    if ([string]::IsNullOrEmpty($Version)) { return $t }
    if ($Status -eq 'Modernise') { return "$t $Version+)" }
    return "$t $Version"
}

function Add-Rule {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')][string]$Severity,
        [string]$Status = 'Deprecated',
        [string]$Version = '',
        [ValidateSet('Code', 'CodeWithStrings', 'StringsOnly', 'Raw')][string]$Scope = 'Code',
        [Parameter(Mandatory = $true)][string]$Pattern,
        [Parameter(Mandatory = $true)][string]$Issue,
        [Parameter(Mandatory = $true)][string]$Fix,
        [string]$Group,
        [string]$Suppress,
        [switch]$CaseSensitive
    )
    if (-not (Test-VersionInScope $Version)) { return }
    $opts = $ciOptions
    if ($CaseSensitive) { $opts = $baseOptions }
    $sup = $null
    if ($Suppress) { $sup = New-Object System.Text.RegularExpressions.Regex($Suppress, $ciOptions) }
    if (-not $Group) { $Group = $Id }
    $Rules.Add([pscustomobject]@{
            Id         = $Id
            Category   = $Category
            Severity   = $Severity
            PhpVersion = (Get-StatusText $Status $Version)
            Scope      = $Scope
            Regex      = (New-Object System.Text.RegularExpressions.Regex($Pattern, $opts))
            Issue      = $Issue
            Fix        = $Fix
            Group      = $Group
            Suppress   = $sup
            IsFunction = $false
        })
}

# Function metadata tables (PHP function names are case-insensitive; PS hashtables are too)
$FuncMeta = @{}
$PrefixMeta = New-Object System.Collections.Generic.List[object]

function New-FuncInfo($Status, $Version, $Severity, $Fix, $Category) {
    if (-not $Category) {
        switch ($Status) {
            'Removed'   { $Category = 'Removed Function' }
            'Unbundled' { $Category = 'Removed Function' }
            default     { $Category = 'Deprecated Function' }
        }
    }
    [pscustomobject]@{ Status = $Status; Version = $Version; Severity = $Severity; Fix = $Fix; Category = $Category }
}

function Add-Func {
    param([Parameter(Position = 0)][string[]]$Name, [Parameter(Position = 1)][string]$Status, [Parameter(Position = 2)][string]$Version,
        [Parameter(Position = 3)][string]$Severity, [Parameter(Position = 4)][string]$Fix, [Parameter(Position = 5)][string]$Category)
    foreach ($n in $Name) { $FuncMeta[$n] = New-FuncInfo $Status $Version $Severity $Fix $Category }
}

function Add-FuncPrefix {
    param([Parameter(Position = 0)][string]$Prefix, [Parameter(Position = 1)][string]$Status, [Parameter(Position = 2)][string]$Version,
        [Parameter(Position = 3)][string]$Severity, [Parameter(Position = 4)][string]$Fix, [Parameter(Position = 5)][string]$Category)
    $info = New-FuncInfo $Status $Version $Severity $Fix $Category
    $info | Add-Member -NotePropertyName Prefix -NotePropertyValue $Prefix
    $PrefixMeta.Add($info)
}

function Resolve-FuncInfo([string]$Name) {
    $info = $FuncMeta[$Name]
    if ($info) { return $info }
    foreach ($p in $PrefixMeta) {
        if ($Name.StartsWith($p.Prefix, [System.StringComparison]::OrdinalIgnoreCase)) { return $p }
    }
    return $null
}
#endregion

#region ---------------------------------------------------------------- Function catalogue
$DB = 'Legacy Database'

# --- Legacy database extensions
Add-Func 'mysql_connect', 'mysql_pconnect' Removed 7.0 Critical "mysqli_connect(`$host, `$user, `$pass, `$db) or new PDO('mysql:host=...;dbname=...;charset=utf8mb4', `$user, `$pass)" $DB
Add-Func 'mysql_select_db' Removed 7.0 Critical "mysqli_select_db(`$link, `$db), or put dbname in the PDO DSN" $DB
Add-Func 'mysql_query', 'mysql_unbuffered_query' Removed 7.0 Critical "mysqli_query(`$link, `$sql) - preferably `$stmt = `$pdo->prepare(`$sql); `$stmt->execute(`$params)" $DB
Add-Func 'mysql_db_query' Removed 7.0 Critical "mysqli_select_db() + mysqli_query(), or PDO prepared statements" $DB
Add-Func 'mysql_fetch_array' Removed 7.0 Critical "mysqli_fetch_array(`$result) or `$stmt->fetch(PDO::FETCH_BOTH)" $DB
Add-Func 'mysql_fetch_assoc' Removed 7.0 Critical "mysqli_fetch_assoc(`$result) or `$stmt->fetch(PDO::FETCH_ASSOC)" $DB
Add-Func 'mysql_fetch_row' Removed 7.0 Critical "mysqli_fetch_row(`$result) or `$stmt->fetch(PDO::FETCH_NUM)" $DB
Add-Func 'mysql_fetch_object' Removed 7.0 Critical "mysqli_fetch_object(`$result) or `$stmt->fetch(PDO::FETCH_OBJ)" $DB
Add-Func 'mysql_num_rows' Removed 7.0 Critical "mysqli_num_rows(`$result) or `$stmt->rowCount() / a COUNT(*) query" $DB
Add-Func 'mysql_affected_rows' Removed 7.0 Critical "mysqli_affected_rows(`$link) or `$stmt->rowCount()" $DB
Add-Func 'mysql_insert_id' Removed 7.0 Critical "mysqli_insert_id(`$link) or `$pdo->lastInsertId()" $DB
Add-Func 'mysql_real_escape_string', 'mysql_escape_string' Removed 7.0 Critical "Use prepared statements with bound parameters (mysqli_real_escape_string(`$link, `$s) only as a stopgap)" $DB
Add-Func 'mysql_error', 'mysql_errno' Removed 7.0 Critical "mysqli_error(`$link) / mysqli_errno(`$link), or enable exceptions (PDO::ERRMODE_EXCEPTION, mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT))" $DB
Add-Func 'mysql_close' Removed 7.0 Critical "mysqli_close(`$link) or `$pdo = null" $DB
Add-Func 'mysql_result' Removed 7.0 Critical "No direct equivalent: fetch the row (mysqli_fetch_row) and index it, or PDOStatement::fetchColumn()" $DB
Add-Func 'mysql_free_result' Removed 7.0 Critical "mysqli_free_result(`$result) or `$stmt->closeCursor()" $DB
Add-Func 'mysql_set_charset' Removed 7.0 Critical "mysqli_set_charset(`$link, 'utf8mb4') or charset=utf8mb4 in the PDO DSN" $DB
Add-Func 'mysql_data_seek' Removed 7.0 Critical "mysqli_data_seek(`$result, `$offset)" $DB
Add-Func 'mysql_num_fields' Removed 7.0 Critical "mysqli_num_fields(`$result) or `$stmt->columnCount()" $DB
Add-Func 'mysql_list_tables', 'mysql_list_dbs', 'mysql_list_fields' Removed 7.0 Critical "Run SHOW TABLES / SHOW DATABASES / SHOW COLUMNS through mysqli or PDO" $DB
Add-FuncPrefix 'mysql_' Removed 7.0 Critical "Migrate to mysqli (procedural mysqli_* take the link as first argument) or PDO with prepared statements" $DB
Add-FuncPrefix 'mssql_' Removed 7.0 Critical "Use the Microsoft sqlsrv_* driver, PDO_SQLSRV or PDO_DBLIB" $DB
Add-FuncPrefix 'sybase_' Removed 7.0 Critical "Use PDO_DBLIB or PDO_SQLSRV" $DB
Add-FuncPrefix 'sqlite_' Removed 5.4 Critical "SQLite 2 extension is gone: use the SQLite3 class or PDO_SQLITE" $DB
Add-FuncPrefix 'msql_' Removed 5.3 Critical "mSQL extension removed: migrate to PDO" $DB
Add-FuncPrefix 'fbsql_' Removed 5.3 Critical "FrontBase extension removed: migrate to PDO/ODBC" $DB
Add-FuncPrefix 'ifx_' Removed 5.2 Critical "Informix extension removed: use PDO_INFORMIX" $DB
Add-FuncPrefix 'ingres_' Unbundled 5.1 High "Install the PECL ingres extension or use ODBC/PDO" $DB
Add-FuncPrefix 'dbase_' Unbundled 5.3 High "Install the PECL dbase extension or convert the data" $DB
Add-FuncPrefix 'ibase_' Unbundled 7.4 High "InterBase/Firebird extension moved to PECL: use PDO_FIREBIRD" $DB
Add-FuncPrefix 'fbird_' Unbundled 7.4 High "InterBase/Firebird extension moved to PECL: use PDO_FIREBIRD" $DB
Add-FuncPrefix 'oci' Unbundled 8.4 Medium "OCI8 is no longer bundled: install the PECL oci8 extension (PDO_OCI is also PECL from 8.4)" $DB
Add-Func 'odbc_result_all' Deprecated 8.1 Medium "Loop with odbc_fetch_array() and render the output yourself" $DB
Add-Func 'mysqli_ping' Deprecated 8.4 Low "Remove; handle connection errors and reconnect explicitly (mysqli.reconnect was removed)" $DB
Add-Func 'mysqli_kill' Deprecated 8.4 Low "Execute 'KILL <thread_id>' with mysqli_query()" $DB
Add-Func 'mysqli_refresh' Deprecated 8.4 Low "Execute the equivalent FLUSH statement with mysqli_query()" $DB
$pgAliases = [ordered]@{
    pg_errormessage = 'pg_last_error'; pg_numrows = 'pg_num_rows'; pg_numfields = 'pg_num_fields'; pg_cmdtuples = 'pg_affected_rows'
    pg_fieldname = 'pg_field_name'; pg_fieldsize = 'pg_field_size'; pg_fieldtype = 'pg_field_type'; pg_fieldnum = 'pg_field_num'
    pg_result = 'pg_fetch_result'; pg_fieldprtlen = 'pg_field_prtlen'; pg_fieldisnull = 'pg_field_is_null'; pg_freeresult = 'pg_free_result'
    pg_getlastoid = 'pg_last_oid'; pg_locreate = 'pg_lo_create'; pg_lounlink = 'pg_lo_unlink'; pg_loopen = 'pg_lo_open'
    pg_loclose = 'pg_lo_close'; pg_loread = 'pg_lo_read'; pg_lowrite = 'pg_lo_write'; pg_loreadall = 'pg_lo_read_all'
    pg_loimport = 'pg_lo_import'; pg_loexport = 'pg_lo_export'; pg_setclientencoding = 'pg_set_client_encoding'; pg_clientencoding = 'pg_client_encoding'
}
foreach ($k in $pgAliases.Keys) { Add-Func $k Deprecated 8.0 Low ("Rename to {0}()" -f $pgAliases[$k]) $DB }

# --- Removed in 5.4
Add-Func 'session_register' Removed 5.4 Critical "Assign directly: `$_SESSION['name'] = `$value;"
Add-Func 'session_unregister' Removed 5.4 Critical "unset(`$_SESSION['name']);"
Add-Func 'session_is_registered' Removed 5.4 Critical "isset(`$_SESSION['name'])"
Add-Func 'import_request_variables' Removed 5.4 Critical "Read values explicitly from `$_GET / `$_POST / `$_COOKIE (or filter_input())"
Add-Func 'define_syslog_variables' Removed 5.4 Critical "Remove the call; LOG_* constants are always defined"

# --- Removed in 7.0
Add-Func 'ereg', 'eregi' Removed 7.0 Critical "preg_match('/pattern/', `$subject) - add delimiters; use the /i modifier for eregi"
Add-Func 'ereg_replace', 'eregi_replace' Removed 7.0 Critical "preg_replace('/pattern/', `$replacement, `$subject) - use /i for eregi_replace"
Add-Func 'split' Removed 7.0 Critical "explode() for a literal delimiter, otherwise preg_split('/pattern/', `$str)"
Add-Func 'spliti' Removed 7.0 Critical "preg_split('/pattern/i', `$str)"
Add-Func 'sql_regcase' Removed 7.0 Critical "Use preg_match() with the /i modifier instead"
Add-Func 'call_user_method' Removed 7.0 Critical "call_user_func([`$obj, 'method'], ...`$args)"
Add-Func 'call_user_method_array' Removed 7.0 Critical "call_user_func_array([`$obj, 'method'], `$args)"
Add-Func 'set_magic_quotes_runtime', 'magic_quotes_runtime' Removed 7.0 Critical "Remove the call; magic quotes no longer exist"
Add-Func 'set_socket_blocking' Removed 7.0 Critical "stream_set_blocking()"
Add-Func 'datefmt_set_timezone_id' Removed 7.0 Critical "datefmt_set_timezone() / IntlDateFormatter::setTimeZone()"
Add-FuncPrefix 'imageps' Removed 7.0 Critical "PostScript Type1 support removed: use FreeType - imagettftext() / imagettfbbox()"

# --- Removed in 7.2 / 7.4
Add-FuncPrefix 'mcrypt_' Removed 7.2 Critical "Migrate to openssl_encrypt()/openssl_decrypt() or sodium_crypto_secretbox(); beware padding/IV differences (phpseclib/mcrypt_compat can decrypt legacy data)"
Add-Func 'mdecrypt_generic' Removed 7.2 Critical "Migrate to openssl_decrypt() or sodium_crypto_secretbox_open()"
Add-FuncPrefix 'wddx_' Removed 7.4 Critical "WDDX extension removed: use json_encode()/json_decode() or serialize()"
Add-FuncPrefix 'recode' Removed 7.4 Critical "Recode extension removed: use mb_convert_encoding() or iconv()"
Add-Func 'hwapi_hgcsp' Removed 5.2 Critical "Remove (Hyperwave API removed)"

# --- Removed in 8.0
Add-Func 'create_function' Removed 8.0 Critical "Use an anonymous function: function (`$a) use (`$b) { ... } or an arrow function fn(`$a) => ..."
Add-Func 'each' Removed 8.0 Critical "foreach (`$array as `$key => `$value) { ... }"
Add-Func 'read_exif_data' Removed 8.0 Critical "exif_read_data()"
Add-Func 'gmp_random' Removed 8.0 Critical "gmp_random_bits() or gmp_random_range()"
Add-Func 'jpeg2wbmp' Removed 8.0 Critical "imagecreatefromjpeg() then imagewbmp()"
Add-Func 'png2wbmp' Removed 8.0 Critical "imagecreatefrompng() then imagewbmp()"
Add-Func 'image2wbmp' Removed 8.0 Critical "imagewbmp()"
Add-Func 'fgetss' Removed 8.0 Critical "strip_tags(fgets(`$handle))"
Add-Func 'gzgetss' Removed 8.0 Critical "strip_tags(gzgets(`$zp))"
Add-Func 'get_magic_quotes_gpc', 'get_magic_quotes_runtime' Removed 8.0 Critical "Remove (always false since 5.4) together with the stripslashes() branch it guards"
Add-Func 'hebrevc' Removed 8.0 Critical "nl2br(hebrev(`$str))"
Add-Func 'convert_cyr_string' Removed 8.0 Critical "mb_convert_encoding() or iconv()"
Add-Func 'money_format' Removed 8.0 Critical "NumberFormatter::formatCurrency() (intl) or number_format()"
Add-Func 'ezmlm_hash' Removed 8.0 Critical "Re-implement in userland or remove"
Add-Func 'restore_include_path' Removed 8.0 Critical "ini_restore('include_path')"
Add-Func 'ldap_sort' Removed 8.0 Critical "Sort the entries in PHP (usort) or use the server-side sort control"
Add-Func 'ldap_control_paged_result', 'ldap_control_paged_result_response' Removed 8.0 Critical "Pass LDAP_CONTROL_PAGEDRESULTS in the `$controls argument of ldap_search() and read it with ldap_parse_result()"
Add-Func 'mbregex_encoding' Removed 8.0 Critical "mb_regex_encoding()"
Add-Func 'mbsplit' Removed 8.0 Critical "mb_split()"
Add-FuncPrefix 'mbereg' Removed 8.0 Critical "Use the mb_ereg* equivalent (mb_ereg(), mb_eregi(), mb_ereg_replace(), mb_ereg_search()...)"
Add-FuncPrefix 'xmlrpc_' Unbundled 8.0 High "XML-RPC extension moved to PECL: install it or use a userland library (e.g. phpxmlrpc/phpxmlrpc)"

# --- Deprecated 8.0
Add-Func 'zip_open', 'zip_read', 'zip_close' Deprecated 8.0 Medium "Use the ZipArchive class"
Add-FuncPrefix 'zip_entry_' Deprecated 8.0 Medium "Use the ZipArchive class (getFromIndex(), statIndex(), ...)"
Add-Func 'libxml_disable_entity_loader' Deprecated 8.0 Low "Remove; external entity loading is disabled by default with libxml >= 2.9"
Add-Func 'openssl_pkey_free', 'openssl_free_key', 'openssl_x509_free' Deprecated 8.0 Low "Remove the call; key/certificate objects are freed automatically"

# --- Deprecated 8.1
Add-Func 'strftime', 'gmstrftime' Deprecated 8.1 Medium "date() / DateTimeInterface::format(), or IntlDateFormatter::format() for localised output"
Add-Func 'strptime' Deprecated 8.1 Medium "date_parse_from_format() or DateTime::createFromFormat()"
Add-Func 'date_sunrise', 'date_sunset' Deprecated 8.1 Medium "date_sun_info()"
Add-FuncPrefix 'mhash' Deprecated 8.1 Medium "hash() / hash_hmac() / hash_algos()"

# --- Deprecated 8.2 / 8.3
Add-Func 'utf8_encode' Deprecated 8.2 Medium "mb_convert_encoding(`$s, 'UTF-8', 'ISO-8859-1')"
Add-Func 'utf8_decode' Deprecated 8.2 Medium "mb_convert_encoding(`$s, 'ISO-8859-1', 'UTF-8')"
Add-Func 'assert_options' Deprecated 8.3 Low "Configure zend.assertions / assert.exception in php.ini instead"

# --- 8.4
Add-Func 'lcg_value' Deprecated 8.4 Low "random_int() or (new \Random\Randomizer())->getFloat(0, 1)"
Add-FuncPrefix 'imap_' Unbundled 8.4 High "IMAP extension moved to PECL: install it or migrate to a library such as webklex/php-imap"
Add-FuncPrefix 'pspell_' Unbundled 8.4 High "Pspell extension moved to PECL: install it or use enchant_*"

# --- 8.5
Add-Func 'curl_close', 'curl_share_close', 'finfo_close', 'imagedestroy', 'xml_parser_free' Deprecated 8.5 Low "Remove the call; it has been a no-op since these resources became objects"
#endregion

#region ---------------------------------------------------------------- Pattern rules
# Shared fragment: not a method/static call, not part of a longer identifier, not namespaced
$NC = '(?<!->|::|[\w$\\])'
$SG = '\$_(?:GET|POST|REQUEST|COOKIE|SESSION|FILES|SERVER|ENV)\b'
$Q = '[''"\x01]'   # a quote char (or blanked double-quoted content)

# ---- Unsafe list()
Add-Rule -Id 'LIST-EACH' -Category 'Unsafe list()' -Severity Critical -Status Removed -Version 8.0 -Group 'fn:each' `
    -Pattern '(?<![\w$>:])list\s*\([^;\r\n]*?\)\s*=\s*each\s*\(' `
    -Issue 'while (list(...) = each(...)) loop - each() was removed in PHP 8.0' `
    -Fix 'foreach ($array as $key => $value) { ... }'
Add-Rule -Id 'LIST-EMPTY' -Category 'Unsafe list()' -Severity Critical -Status Removed -Version 7.0 -Group 'list' `
    -Pattern '(?<![\w$>:])list\s*\(\s*(?:,\s*)*\)\s*=' `
    -Issue 'Empty list() assignment is a fatal error since PHP 7.0' `
    -Fix 'Remove the empty list() or name at least one target variable'
Add-Rule -Id 'LIST-APPEND-ORDER' -Category 'Unsafe list()' -Severity High -Status BehaviourChange -Version 7.0 -Group 'list' `
    -Pattern '(?<![\w$>:])list\s*\([^;=\r\n]*?\$\w+(?:->\w+)?\s*\[\s*\][^;=\r\n]*\)\s*=' `
    -Issue 'list() with $array[] targets: assignment order changed in PHP 7.0 (left-to-right), so element order differs from PHP 5' `
    -Fix 'Assign explicitly, e.g. [$a, $b] = $src; $arr[] = $a; $arr[] = $b; or use array_merge()'
Add-Rule -Id 'LIST-STRING' -Category 'Unsafe list()' -Severity High -Status BehaviourChange -Version 7.0 -Group 'list' `
    -Pattern ('(?<![\w$>:])list\s*\([^;\r\n]*?\)\s*=\s*' + $Q) `
    -Issue 'list() can no longer unpack strings (PHP 7.0) - all targets become null' `
    -Fix 'Split the string first: [$a, $b] = str_split($str);'
Add-Rule -Id 'LIST-SHORTFALL' -Category 'Unsafe list()' -Severity Medium -Status BehaviourChange -Version 8.0 -Group 'list' `
    -Pattern '(?<![\w$>:])list\s*\([^;\r\n]*?\)\s*=\s*(?:\$\w+\s*->\s*)?(?:explode|preg_split|str_getcsv|fgetcsv|sscanf|mysql_fetch_\w+|mysqli_fetch_\w+|pg_fetch_\w+|fetch\w*|getimagesize|parse_url|array_slice)\s*\(' `
    -Issue 'list() from a source that can return fewer elements or false/null: missing keys raise "Undefined array key" warnings in PHP 8' `
    -Fix 'Pad or validate first: [$a, $b] = array_pad(explode(":", $s, 2), 2, null); or check the result is an array'
Add-Rule -Id 'LIST-MODERNISE' -Category 'Unsafe list()' -Severity Info -Status Modernise -Version 7.1 -Group 'list' `
    -Pattern '(?<![\w$>:]|function\s+&?\s*)list\s*\(' -Suppress '(?<![\w$>:])each\s*\(|phpscan' `
    -Issue 'list() destructuring - verify the right-hand side is always an array with the expected keys' `
    -Fix 'Prefer short syntax [$a, $b] = $arr (PHP 7.1+) and guard with is_array() / array_pad()'

# ---- Unsafe count()
$countGuard = 'is_countable|is_array|instanceof\s+\\?Countable|\(\s*array\s*\)|\?\?\s*(?:\[\s*\]|array\s*\(\s*\))|is_iterable|phpscan'
Add-Rule -Id 'COUNT-SCALAR' -Category 'Unsafe count()' -Severity Critical -Status BehaviourChange -Version 8.0 -Group 'count' `
    -Pattern ($NC + '(?:count|sizeof)\s*\(\s*(?:' + $Q + '|-?\d|null\b|true\b|false\b)') `
    -Issue 'count() on a scalar/null literal throws TypeError in PHP 8.0' `
    -Fix 'Remove the count() or pass an array / Countable'
Add-Rule -Id 'COUNT-FALSY-SOURCE' -Category 'Unsafe count()' -Severity High -Status BehaviourChange -Version 8.0 -Group 'count' `
    -Pattern ($NC + '(?:count|sizeof)\s*\(\s*(?:\$\w+\s*->\s*)?(?:mysql_fetch_\w+|mysqli_fetch_\w+|pg_fetch_\w+|fetch\w*|glob|file|scandir|json_decode|unserialize|simplexml_load_\w+|getimagesize|parse_url|fgetcsv|ldap_get_entries|odbc_fetch_\w+|db2_fetch_\w+)\s*\(') `
    -Issue 'count() on a function result that can be false/null on failure - TypeError in PHP 8.0 (warning since 7.2)' `
    -Fix 'Store the result and check it: $rows = f(); $n = is_array($rows) ? count($rows) : 0;'
Add-Rule -Id 'COUNT-SUPERGLOBAL' -Category 'Unsafe count()' -Severity High -Status BehaviourChange -Version 8.0 -Group 'count' `
    -Pattern ($NC + '(?:count|sizeof)\s*\(\s*' + $SG + '\s*\[') -Suppress $countGuard `
    -Issue 'count() on request input that may be missing (null) or a string - TypeError in PHP 8.0' `
    -Fix 'count((array)($_POST["x"] ?? [])) or validate with is_array() first'
Add-Rule -Id 'COUNT-VARIABLE' -Category 'Unsafe count()' -Severity Medium -Status BehaviourChange -Version 8.0 -Group 'count' `
    -Pattern ($NC + '(?:count|sizeof)\s*\(\s*\$(?!_(?:GET|POST|REQUEST|COOKIE|SESSION|FILES|SERVER|ENV)\b)\w+(?:\s*(?:->|::)\s*\$?\w+|\s*\[[^\]\r\n]*\])*\s*(?:,[^)\r\n]*)?\)') `
    -Suppress $countGuard `
    -Issue 'count() on a variable that is not proven to be array|Countable - null, false or strings throw TypeError in PHP 8.0' `
    -Fix 'Guard it: is_countable($x) ? count($x) : 0, count((array)$x), or initialise with $x = [] / $x ?? []'

# ---- Unsafe strlen()
$strlenGuard = 'is_string|\(\s*string\s*\)|\?\?\s*' + "['""]" + '|isset\s*\(|!\s*empty\s*\(|is_null|[!=]==?\s*null|null\s*[!=]==?|strval\s*\(|phpscan'
Add-Rule -Id 'STRLEN-SUPERGLOBAL' -Category 'Unsafe strlen()' -Severity High -Status BehaviourChange -Version 8.0 -Group 'strlen' `
    -Pattern ($NC + '(?:mb_|iconv_)?strlen\s*\(\s*' + $SG) -Suppress $strlenGuard `
    -Issue 'strlen() on request input: an array (?x[]=1) throws TypeError (8.0), a missing key passes null (deprecated 8.1)' `
    -Fix 'Validate first: $v = $_GET["x"] ?? ""; if (!is_string($v)) { ... } strlen($v) - or use filter_input()'
Add-Rule -Id 'STRLEN-NULLABLE-SOURCE' -Category 'Unsafe strlen()' -Severity Medium -Status Deprecated -Version 8.1 -Group 'strlen' `
    -Pattern ($NC + '(?:mb_|iconv_)?strlen\s*\(\s*(?:\$\w+\s*->\s*)?(?:fgets|fread|file_get_contents|getenv|filter_input|filter_var|json_encode|preg_replace|ini_get|readline|stream_get_contents|stream_get_line|ob_get_clean|ob_get_contents|shell_exec|mysql_result|\w*fetch\w*|session_id|get_cfg_var)\s*\(') `
    -Issue 'strlen() on a function result that can be false/null - passing null is deprecated in PHP 8.1' `
    -Fix 'Store and check the result first: $s = f(); if ($s !== false && $s !== null) { strlen($s); }'
Add-Rule -Id 'STRLEN-EMPTY-TEST' -Category 'Unsafe strlen()' -Severity Low -Status Deprecated -Version 8.1 -Group 'strlen' `
    -Pattern ($NC + '(?:mb_)?strlen\s*\((?:[^()\r\n]|\([^()\r\n]*\))*\)\s*(?:===?|!==?|<=?|>=?)\s*0\b|\b0\s*(?:===?|!==?|<|>)\s*(?:mb_)?strlen\s*\(|!\s*(?:mb_)?strlen\s*\(|\b(?:if|elseif|while)\s*\(\s*(?:mb_)?strlen\s*\((?:[^()\r\n]|\([^()\r\n]*\))*\)\s*\)') `
    -Suppress $strlenGuard `
    -Issue 'strlen() used as an emptiness test - null arguments are deprecated in PHP 8.1 (TypeError for arrays)' `
    -Fix 'Compare directly: $x !== "" (or ($x ?? "") !== "" when null is possible)'
Add-Rule -Id 'STRLEN-VARIABLE' -Category 'Unsafe strlen()' -Severity Low -Status Deprecated -Version 8.1 -Group 'strlen' `
    -Pattern ($NC + '(?:mb_|iconv_)?strlen\s*\(\s*\$\w+') -Suppress $strlenGuard `
    -Issue 'strlen() on a variable that may be null - deprecated in PHP 8.1 (arrays throw TypeError since 8.0)' `
    -Fix 'Ensure a string: strlen($x ?? "") or strlen((string)$x)'

# ---- Null / type safety for internal string functions fed directly from request input
Add-Rule -Id 'NULLARG-REQUEST' -Category 'Type Safety' -Severity Medium -Status Deprecated -Version 8.1 -Group 'nullarg' `
    -Pattern ($NC + '(?:trim|ltrim|rtrim|htmlspecialchars|htmlentities|html_entity_decode|strtolower|strtoupper|ucfirst|ucwords|str_replace|str_ireplace|explode|strpos|stripos|strrpos|substr|str_pad|preg_match|preg_replace|preg_split|urlencode|rawurlencode|urldecode|addslashes|stripslashes|strip_tags|nl2br|md5|sha1|base64_decode|base64_encode|json_decode|strcmp|strcasecmp|str_contains|str_starts_with|str_ends_with|number_format|mb_strtolower|mb_strtoupper|mb_substr|mb_strpos|ctype_\w+)\s*\((?:[^;()\r\n]*?,)?\s*\$_(?:GET|POST|REQUEST|COOKIE)\s*\[') `
    -Suppress '\?\?|isset\s*\(|filter_input|is_string|phpscan' `
    -Issue 'Request value passed straight into a string function: missing keys pass null (deprecated 8.1), arrays throw TypeError (8.0)' `
    -Fix 'Use ($_GET["x"] ?? "") after checking is_string(), or filter_input(INPUT_GET, "x")'

# ---- Removed / deprecated syntax
Add-Rule -Id 'SYN-CURLY-OFFSET' -Category 'Removed Syntax' -Severity Critical -Status Removed -Version 8.0 `
    -Pattern '\$[A-Za-z_]\w*(?:->\w+|\[[^\]\r\n]*\])*\{' `
    -Issue 'Curly-brace string/array offset ($str{0}) is a fatal error in PHP 8.0' `
    -Fix 'Use square brackets: $str[0]'
Add-Rule -Id 'SYN-REAL-CAST' -Category 'Removed Syntax' -Severity Critical -Status Removed -Version 8.0 `
    -Pattern '\(\s*real\s*\)' -Issue '(real) cast was removed in PHP 8.0' -Fix 'Use (float)'
Add-Rule -Id 'SYN-UNSET-CAST' -Category 'Removed Syntax' -Severity Critical -Status Removed -Version 8.0 `
    -Pattern '\(\s*unset\s*\)' -Issue '(unset) cast was removed in PHP 8.0' -Fix 'Assign null or call unset($var)'
Add-Rule -Id 'SYN-NONCANONICAL-CAST' -Category 'Deprecated Syntax' -Severity Low -Status Deprecated -Version 8.5 `
    -Pattern '\(\s*(?:boolean|integer|double|binary)\s*\)' -Issue 'Non-canonical cast names are deprecated in PHP 8.5' `
    -Fix 'Use (bool), (int), (float) or (string)'
Add-Rule -Id 'SYN-AUTOLOAD' -Category 'Removed Syntax' -Severity Critical -Status Removed -Version 8.0 `
    -Pattern '(?<![\w$>:])function\s+__autoload\s*\(' -Issue '__autoload() is no longer called (removed in PHP 8.0)' `
    -Fix 'spl_autoload_register(function ($class) { ... }); or Composer autoloading'
Add-Rule -Id 'SYN-PHP-ERRORMSG' -Category 'Removed Syntax' -Severity Critical -Status Removed -Version 8.0 `
    -Pattern '\$php_errormsg\b' -Issue '$php_errormsg (track_errors) was removed in PHP 8.0' `
    -Fix 'error_get_last()["message"]'
Add-Rule -Id 'SYN-HTTP-VARS' -Category 'Removed Syntax' -Severity Critical -Status Removed -Version 5.4 `
    -Pattern '\$HTTP_(?:GET|POST|COOKIE|SERVER|ENV|SESSION|POST_FILES)_VARS\b' -Issue 'Long $HTTP_*_VARS arrays were removed in PHP 5.4' `
    -Fix 'Use $_GET, $_POST, $_COOKIE, $_SERVER, $_ENV, $_SESSION or $_FILES'
Add-Rule -Id 'SYN-RAW-POST-DATA' -Category 'Removed Syntax' -Severity Critical -Status Removed -Version 7.0 `
    -Pattern '\$HTTP_RAW_POST_DATA\b' -Issue '$HTTP_RAW_POST_DATA was removed in PHP 7.0' `
    -Fix 'file_get_contents("php://input")'
Add-Rule -Id 'SYN-NEW-BYREF' -Category 'Removed Syntax' -Severity Critical -Status Removed -Version 7.0 `
    -Pattern '=\s*&\s*new\b' -Issue 'Assigning the result of new by reference (=& new) is a parse error since PHP 7.0' `
    -Fix 'Drop the ampersand: $obj = new Foo();'
Add-Rule -Id 'SYN-PREG-E' -Category 'Removed Syntax' -Severity Critical -Status Removed -Version 7.0 -Scope CodeWithStrings `
    -Pattern 'preg_replace\s*\(\s*(?<q>[''"])(?<d>[^\w\s\\{(\[<])(?:(?!\k<q>).)*?\k<d>[a-zA-Z]*e[a-zA-Z]*\k<q>' -CaseSensitive `
    -Issue 'preg_replace() /e modifier was removed in PHP 7.0' `
    -Fix 'preg_replace_callback($pattern, function ($m) { return ...; }, $subject)'
Add-Rule -Id 'SYN-ASP-TAGS' -Category 'Removed Syntax' -Severity Medium -Status Removed -Version 7.0 -Scope Raw `
    -Pattern '<%(?!--)[=\s]' -Issue 'ASP-style tags (<% %>) were removed in PHP 7.0 (ignore if this is a JavaScript template)' `
    -Fix 'Use <?php ... ?> or <?= ... ?>'
Add-Rule -Id 'SYN-SCRIPT-PHP' -Category 'Removed Syntax' -Severity Critical -Status Removed -Version 7.0 -Scope Raw `
    -Pattern '<script\s+language\s*=\s*[''"]?php' -Issue '<script language="php"> tags were removed in PHP 7.0' `
    -Fix 'Use <?php ... ?>'
Add-Rule -Id 'SYN-SHORT-OPEN-TAG' -Category 'Deprecated Syntax' -Severity Medium -Status Risk -Scope Raw `
    -Pattern '<\?(?![pP][hH][pP]\b|=|xml)' `
    -Issue 'Short open tag <? depends on short_open_tag, which is off in production php.ini defaults' `
    -Fix 'Use <?php (or <?= for echo)'
Add-Rule -Id 'SYN-NESTED-TERNARY' -Category 'Removed Syntax' -Severity High -Status Removed -Version 8.0 `
    -Pattern '\?(?![>:?])[^;?:()\r\n{}]+:(?!:)[^;?:()\r\n{}]+\?(?![>:?])[^;?:()\r\n{}]*:' `
    -Issue 'Possible unparenthesised nested ternary (a ? b : c ? d : e) - fatal error in PHP 8.0' `
    -Fix 'Add parentheses: ($a ? $b : $c) ? $d : $e  or  $a ? $b : ($c ? $d : $e)'
Add-Rule -Id 'SYN-PARSE-STR-1ARG' -Category 'Removed Syntax' -Severity Critical -Status Removed -Version 8.0 `
    -Pattern ($NC + 'parse_str\s*\(\s*[^,;()\r\n]*(?:\([^()\r\n]*\)[^,;()\r\n]*)*\)') `
    -Issue 'parse_str() without a result array was removed in PHP 8.0 (it used to create local variables)' `
    -Fix 'parse_str($str, $output); then read $output["key"]'
Add-Rule -Id 'SYN-DEFINE-CI' -Category 'Removed Syntax' -Severity High -Status Removed -Version 8.0 `
    -Pattern ($NC + 'define\s*\(\s*[^,;\r\n]+,[^;\r\n]+,\s*true\s*\)') `
    -Issue 'Case-insensitive constants (define(..., true)) are not supported in PHP 8.0' `
    -Fix 'Remove the third argument and use the constant with its exact case'
Add-Rule -Id 'SYN-ASSERT-STRING' -Category 'Removed Syntax' -Severity Critical -Status Removed -Version 8.0 -Scope CodeWithStrings `
    -Pattern ($NC + 'assert\s*\(\s*[''"]') -Issue 'assert() with a string argument is no longer evaluated (PHP 8.0)' `
    -Fix 'Pass an expression: assert($x > 0);'
Add-Rule -Id 'SYN-IMPLODE-ORDER' -Category 'Removed Syntax' -Severity Critical -Status Removed -Version 8.0 -Scope CodeWithStrings `
    -Pattern ($NC + '(?:implode|join)\s*\(\s*\$[\w\->\[\]''"]+\s*,\s*[''"]') `
    -Issue 'implode($array, $glue) legacy argument order was removed in PHP 8.0' `
    -Fix 'Put the glue first: implode(", ", $array)'
Add-Rule -Id 'SYN-GLOBALS-WRITE' -Category 'Removed Syntax' -Severity Critical -Status Removed -Version 8.1 `
    -Pattern '\$GLOBALS\s*=(?!=)' -Issue 'Writing to the whole $GLOBALS array is a compile error in PHP 8.1' `
    -Fix 'Write individual keys: $GLOBALS["name"] = $value;'
Add-Rule -Id 'SYN-DOLLAR-BRACE' -Category 'Deprecated Syntax' -Severity Medium -Status Deprecated -Version 8.2 -Scope StringsOnly `
    -Pattern '\$\{\s*[A-Za-z_]' -Issue '"${var}" string interpolation is deprecated in PHP 8.2' `
    -Fix 'Use "{$var}" (or "{${expr}}" -> "{$var[expr]}")'
Add-Rule -Id 'SYN-CALLABLE-STRING' -Category 'Deprecated Syntax' -Severity Medium -Status Deprecated -Version 8.2 -Scope CodeWithStrings `
    -Pattern '[''"](?:self|parent|static)::\w+[''"]|\[\s*[''"](?:self|parent|static)[''"]\s*,' `
    -Issue 'Partially supported callables ("self::method", ["parent", "m"]) are deprecated in PHP 8.2' `
    -Fix 'Use [self::class, "method"], static::method(...) first-class callable syntax or a closure'
Add-Rule -Id 'SYN-IMPLICIT-NULLABLE' -Category 'Deprecated Syntax' -Severity Medium -Status Deprecated -Version 8.4 `
    -Pattern '[(,]\s*(?!(?:mixed|null|as|use|new|clone|return|echo|print|yield|and|or|xor|instanceof|case|global|static|public|private|protected|readonly|var|const)\b)\\?[A-Za-z_][\w\\]*\s+&?(?:\.\.\.)?\$\w+\s*=\s*null\b' `
    -Issue 'Implicitly nullable parameter type (Type $x = null) is deprecated in PHP 8.4' `
    -Fix 'Make it explicit: ?Type $x = null'
Add-Rule -Id 'SYN-OPTIONAL-BEFORE-REQUIRED' -Category 'Deprecated Syntax' -Severity Medium -Status Deprecated -Version 8.0 `
    -Pattern '(?<![\w$>:])function\b[^(;{]*\((?:[^()]*?,)?\s*(?:\??[\w\\|]+\s+)?&?\$\w+\s*=\s*[^,()\[\];]+,\s*(?:\??[\w\\|]+\s+)?&?\$\w+\s*(?=[,)])' `
    -Issue 'Optional parameter declared before a required one - deprecated in PHP 8.0 (the default is ignored)' `
    -Fix 'Reorder the parameters or remove the default value'
Add-Rule -Id 'SYN-GET-CLASS-NOARGS' -Category 'Deprecated Syntax' -Severity Low -Status Deprecated -Version 8.3 `
    -Pattern ($NC + 'get_(?:parent_)?class\s*\(\s*\)') -Issue 'get_class()/get_parent_class() without arguments is deprecated in PHP 8.3' `
    -Fix 'Use self::class / static::class / parent::class, or get_class($this)'
Add-Rule -Id 'SYN-USER-ERROR' -Category 'Deprecated Syntax' -Severity Low -Status Deprecated -Version 8.4 `
    -Pattern ($NC + 'trigger_error\s*\([^;\r\n]*\bE_USER_ERROR\b') -Issue 'trigger_error() with E_USER_ERROR is deprecated in PHP 8.4' `
    -Fix 'Throw an exception, or log and call exit() explicitly'
Add-Rule -Id 'SYN-RESERVED-CLASS' -Category 'Removed Syntax' -Severity Critical -Status Removed -Version 7.0 `
    -Pattern '(?<![\w$>:])(?:class|interface|trait)\s+(?:object|iterable|void|bool|int|float|string|true|false|null|mixed|never|match)\b' `
    -Issue 'Class/interface/trait name is a reserved word in PHP 7/8 (e.g. String, Object, Match)' `
    -Fix 'Rename the type (and update all references)'

# ---- Constants / variables / ini
Add-Rule -Id 'CONST-MYSQL' -Category $DB -Severity Critical -Status Removed -Version 7.0 -CaseSensitive `
    -Pattern '(?<![\w:$\\])MYSQL_(?:ASSOC|NUM|BOTH|CLIENT_COMPRESS|CLIENT_IGNORE_SPACE|CLIENT_INTERACTIVE|CLIENT_SSL)\b' `
    -Issue 'ext/mysql constant (removed with the extension in PHP 7.0)' -Fix 'MYSQLI_ASSOC / MYSQLI_NUM / MYSQLI_BOTH or PDO::FETCH_ASSOC / FETCH_NUM / FETCH_BOTH'
Add-Rule -Id 'CONST-FILTER-STRING' -Category 'Deprecated Function' -Severity Medium -Status Deprecated -Version 8.1 -CaseSensitive `
    -Pattern '\bFILTER_SANITIZE_(?:STRING|STRIPPED)\b' -Issue 'FILTER_SANITIZE_STRING / FILTER_SANITIZE_STRIPPED are deprecated in PHP 8.1' `
    -Fix 'Escape on output with htmlspecialchars(), or use FILTER_UNSAFE_RAW plus explicit validation'
Add-Rule -Id 'CONST-FILTER-FLAGS' -Category 'Removed Function' -Severity High -Status Removed -Version 8.0 -CaseSensitive `
    -Pattern '\bFILTER_FLAG_(?:SCHEME|HOST)_REQUIRED\b' -Issue 'FILTER_FLAG_SCHEME_REQUIRED / FILTER_FLAG_HOST_REQUIRED were removed in PHP 8.0' `
    -Fix 'Remove the flag; FILTER_VALIDATE_URL always requires scheme and host'
Add-Rule -Id 'CONST-INTL-IDNA-2003' -Category 'Removed Function' -Severity High -Status Removed -Version 8.0 -CaseSensitive `
    -Pattern '\bINTL_IDNA_VARIANT_2003\b' -Issue 'INTL_IDNA_VARIANT_2003 was removed in PHP 8.0' -Fix 'Use INTL_IDNA_VARIANT_UTS46'
Add-Rule -Id 'CONST-MT-RAND-PHP' -Category 'Deprecated Function' -Severity Low -Status Deprecated -Version 8.3 -CaseSensitive `
    -Pattern '\bMT_RAND_PHP\b' -Issue 'MT_RAND_PHP (biased legacy mt_rand) is deprecated in PHP 8.3' -Fix 'Use MT_RAND_MT19937 (default) or Random\Randomizer'
Add-Rule -Id 'CONST-E-STRICT' -Category 'Deprecated Function' -Severity Low -Status Deprecated -Version 8.4 -CaseSensitive `
    -Pattern '\bE_STRICT\b' -Issue 'E_STRICT is deprecated in PHP 8.4 (no E_STRICT errors exist since 8.0)' -Fix 'Remove E_STRICT from error_reporting() expressions'
Add-Rule -Id 'VAR-HTTP-RESPONSE-HEADER' -Category 'Deprecated Syntax' -Severity Low -Status Deprecated -Version 8.5 `
    -Pattern '\$http_response_header\b' -Issue '$http_response_header is deprecated in PHP 8.5' -Fix 'http_get_last_response_headers()'
Add-Rule -Id 'PDO-DRIVER-CONSTANTS' -Category $DB -Severity Low -Status Deprecated -Version 8.5 -CaseSensitive `
    -Pattern 'PDO::(?:MYSQL_ATTR_|PGSQL_ATTR_|SQLITE_ATTR_|SQLITE_OPEN_|SQLITE_DETERMINISTIC|PGSQL_TRANSACTION_)\w*' `
    -Issue 'Driver-specific constants on the PDO class are deprecated in PHP 8.5' `
    -Fix 'Use the driver subclass constants, e.g. Pdo\Mysql::ATTR_INIT_COMMAND, Pdo\Sqlite::DETERMINISTIC'
Add-Rule -Id 'INI-REMOVED' -Category 'Configuration' -Severity High -Status Removed -Scope CodeWithStrings `
    -Pattern ($NC + 'ini_(?:set|get|restore|alter)\s*\(\s*[''"](?:track_errors|magic_quotes_gpc|magic_quotes_runtime|magic_quotes_sybase|safe_mode\w*|register_globals|register_long_arrays|allow_call_time_pass_reference|y2k_compliance|asp_tags|always_populate_raw_post_data|mbstring\.func_overload|sql\.safe_mode|session\.bug_compat_\w+|zend\.ze1_compatibility_mode|mcrypt\.\w+|define_syslog_variables)[''"]') `
    -Issue 'ini directive that no longer exists in modern PHP' -Fix 'Remove the call and any logic that depends on the directive'

# ---- Database security
Add-Rule -Id 'DB-SQL-CONCAT' -Category 'Database Security' -Severity High -Status Risk -Scope CodeWithStrings -Group 'sql' `
    -Pattern '(?:mysql_query|mysql_db_query|mysql_unbuffered_query|mysqli_query|mysqli_multi_query|mysqli_real_query|pg_query|mssql_query|sqlsrv_query|odbc_exec|sqlite_query|->query|->exec|->multi_query|->real_query|->prepare)\s*\((?:[^;\r\n]*?,)?\s*(?:"[^"\r\n]*\$[A-Za-z_{]|[''"][^''"\r\n]*[''"]\s*\.\s*\$|\$\w+\s*\.)' `
    -Issue 'SQL query built by concatenating/interpolating variables (SQL injection risk)' `
    -Fix 'Use prepared statements: $stmt = $pdo->prepare("... WHERE id = ?"); $stmt->execute([$id]);'
Add-Rule -Id 'DB-SQL-BUILD' -Category 'Database Security' -Severity Medium -Status Risk -Scope CodeWithStrings -Group 'sql' `
    -Pattern '[''"]\s*(?:SELECT\b[^''";\r\n]*?\bFROM\b|INSERT\s+INTO\b|UPDATE\s+\S+\s+SET\b|DELETE\s+FROM\b|REPLACE\s+INTO\b)[^''";\r\n]*(?:\$[A-Za-z_{]|[''"]\s*\.\s*\$)' `
    -Issue 'SQL string assembled from variables (SQL injection risk)' `
    -Fix 'Use placeholders (?, :name) and bind the values with prepared statements'
Add-Rule -Id 'DB-ADDSLASHES' -Category 'Database Security' -Severity Medium -Status Risk `
    -Pattern ($NC + 'addslashes\s*\(') -Issue 'addslashes() is not a safe SQL escaping mechanism (charset issues)' `
    -Fix 'Use prepared statements; for other contexts use the proper escaping function'
Add-Rule -Id 'DB-MANUAL-ESCAPE' -Category 'Database Security' -Severity Low -Status Risk `
    -Pattern ($NC + '(?:mysqli_real_escape_string|mysqli_escape_string|pg_escape_string|sqlite_escape_string)\s*\(|->real_escape_string\s*\(') `
    -Issue 'Manual SQL escaping - easy to miss a value or mis-quote' -Fix 'Prefer prepared statements with bound parameters'

# ---- Compatibility layers
$removedNames = 'mysql_\w+|mssql_\w+|sybase_\w+|ereg\w*|split|spliti|sql_regcase|each|create_function|mcrypt_\w+|get_magic_quotes_\w+|set_magic_quotes_runtime|money_format|utf8_encode|utf8_decode|session_register|session_unregister|session_is_registered|call_user_method\w*|strftime|hebrevc|convert_cyr_string|fgetss'
Add-Rule -Id 'COMPAT-SHIM-GUARD' -Category 'Compatibility Layer' -Severity Medium -Status Compat -Scope CodeWithStrings `
    -Pattern ('function_exists\s*\(\s*[''"]\\?(?:' + $removedNames + ')[''"]\s*\)') `
    -Issue 'function_exists() guard for a removed/deprecated function - usually wraps a compatibility shim' `
    -Fix 'Migrate callers to the modern API, then delete the shim'
Add-Rule -Id 'COMPAT-SHIM-DEFINITION' -Category 'Compatibility Layer' -Severity High -Status Compat `
    -Pattern ('(?<![\w$>:])function\s+&?\s*(?:' + $removedNames + ')\s*\(') `
    -Suppress '(?:public|private|protected|abstract|final)\s+(?:static\s+)?function' `
    -Issue 'Userland re-implementation (shim) of a removed PHP function' `
    -Fix 'Replace calls with the modern API (mysqli/PDO, preg_*, openssl ...) and remove the shim'
Add-Rule -Id 'COMPAT-POLYFILL-GUARD' -Category 'Compatibility Layer' -Severity Low -Status Compat -Scope CodeWithStrings `
    -Pattern 'function_exists\s*\(\s*[''"]\\?(?:str_contains|str_starts_with|str_ends_with|array_key_first|array_key_last|is_countable|is_iterable|random_bytes|random_int|password_hash|password_verify|hash_equals|array_is_list|mb_str_split|intdiv|json_validate|array_find|array_any|array_all|array_column|boolval|hex2bin|http_response_code|spl_object_id|fdiv|get_debug_type|preg_last_error_msg|mb_str_pad)[''"]' `
    -Issue 'Polyfill for a function that is native in modern PHP' -Fix 'Remove the polyfill once the minimum PHP version provides it'
Add-Rule -Id 'COMPAT-INCLUDE' -Category 'Compatibility Layer' -Severity Medium -Status Compat -Scope CodeWithStrings `
    -Pattern '(?<![\w$])(?:require|include)(?:_once)?\b[^;\r\n]*?(?:mysql2i|mysql[_-]?shim|php7[_-]mysql|mysqli?[_-]compat|mcrypt[_-]compat|ereg\w*compat|random[_-]compat|password[_-]compat|polyfill|compat(?:ibility)?|shim|legacy)[^;\r\n]*;' `
    -Issue 'Includes a compatibility / polyfill / legacy layer' -Fix 'Check what the layer emulates; migrate the callers and drop the include'
Add-Rule -Id 'COMPAT-MYSQL2I' -Category 'Compatibility Layer' -Severity High -Status Compat `
    -Pattern '\bmysql2i\b' -Issue 'mysql2i compatibility class (mysql_* emulation on mysqli)' -Fix 'Migrate to mysqli/PDO directly and remove mysql2i'
Add-Rule -Id 'COMPAT-VERSION-BRANCH' -Category 'Compatibility Layer' -Severity Low -Status Compat -Scope CodeWithStrings `
    -Pattern 'version_compare\s*\(\s*(?:PHP_VERSION|phpversion\s*\(\s*\))\s*,\s*[''"][4-7]\.|PHP_VERSION_ID\s*(?:<=?|>=?|[!=]==?)\s*[4-7]0\d{3}\b|PHP_MAJOR_VERSION\s*(?:<=?|>=?|[!=]==?)\s*[4-7]\b' `
    -Issue 'Branch on a legacy PHP version - one side is dead code on the target version' -Fix 'Remove the obsolete branch'
Add-Rule -Id 'COMPAT-REGISTER-GLOBALS' -Category 'Compatibility Layer' -Severity High -Status Risk `
    -Pattern ($NC + 'extract\s*\(\s*' + $SG) -Issue 'register_globals emulation via extract() on request data (security risk)' `
    -Fix 'Read the required keys explicitly from the superglobal and validate them'

# ---- Combined function rule (added last so specific rules above win de-duplication ties)
$exactNames = @($FuncMeta.Keys | Where-Object { Test-VersionInScope $FuncMeta[$_].Version } | Sort-Object Length -Descending | ForEach-Object { [regex]::Escape($_) })
$prefixPats = @($PrefixMeta | Where-Object { Test-VersionInScope $_.Version } | ForEach-Object { [regex]::Escape($_.Prefix) + '\w*' })
$allFn = @($exactNames) + @($prefixPats)
if ($allFn.Count -gt 0) {
    $fnPattern = '(?<!->|::|[\w$\\]|function\s+&?\s*|new\s+)\\?(?<fn>' + ($allFn -join '|') + ')\s*\('
    $Rules.Add([pscustomobject]@{
            Id = 'FN'; Category = ''; Severity = ''; PhpVersion = ''; Scope = 'Code'
            Regex = (New-Object System.Text.RegularExpressions.Regex($fnPattern, $ciOptions))
            Issue = ''; Fix = ''; Group = ''; Suppress = $null; IsFunction = $true
        })
}

$reClassDecl = New-Object System.Text.RegularExpressions.Regex('(?<![\w$>:])class\s+(?<name>[A-Za-z_]\w*)', $ciOptions)
$reConstruct = New-Object System.Text.RegularExpressions.Regex('function\s+&?\s*__construct\s*\(', $ciOptions)
$reNamespace = New-Object System.Text.RegularExpressions.Regex('(?<![\w$>:\\])namespace\s+[A-Za-z_][\w\\]*\s*[;{]', $ciOptions)
#endregion

#region ---------------------------------------------------------------- Helpers
function New-Finding {
    param($File, $Line, $Column, $Severity, $Category, $RuleId, $Issue, $PhpVersion, $Fix, $Match, $Code)
    [pscustomobject]@{
        Severity     = $Severity
        Category     = $Category
        File         = $File
        Line         = $Line
        Column       = $Column
        RuleId       = $RuleId
        Issue        = $Issue
        PhpVersion   = $PhpVersion
        SuggestedFix = $Fix
        Match        = $Match
        Code         = $Code
    }
}

function Get-RelativePath([string]$Full, [string]$Root) {
    if ($Full.StartsWith($Root, [System.StringComparison]::OrdinalIgnoreCase)) {
        $rel = $Full.Substring($Root.Length).TrimStart('\', '/')
        if ($rel) { return $rel }
    }
    return $Full
}

function New-GitIgnoreMatcher {
    # Builds a matcher rooted at the enclosing Git repository (or the scan root when not in a repo) and
    # pre-loads .git/info/exclude plus every .gitignore between the repository root and the scan root.
    param([string]$ScanRoot)
    $repoRoot = $null
    $probe = $ScanRoot
    while ($probe) {
        if (Test-Path -LiteralPath (Join-Path $probe '.git')) { $repoRoot = $probe; break }
        $parent = [System.IO.Path]::GetDirectoryName($probe.TrimEnd('\', '/'))
        if ([string]::IsNullOrEmpty($parent) -or $parent -eq $probe) { break }
        $probe = $parent
    }
    if (-not $repoRoot) { $repoRoot = $ScanRoot }
    $m = New-GitIgnoreState $repoRoot
    $gitDir = Join-Path $repoRoot '.git'
    if (Test-Path -LiteralPath $gitDir -PathType Container) {
        Add-GitIgnoreFileFor $m (Join-Path $gitDir 'info\exclude') $repoRoot
    }
    # ancestors of the scan root inside the repository (the scan root itself is loaded by the walker)
    $chain = New-Object System.Collections.Generic.List[string]
    $d = [System.IO.Path]::GetDirectoryName($ScanRoot.TrimEnd('\', '/'))
    $full = [System.IO.Path]::GetFullPath($repoRoot).TrimEnd('\', '/')
    while ($d -and $d.Length -ge $full.Length -and $d.StartsWith($full, [System.StringComparison]::OrdinalIgnoreCase)) {
        $chain.Insert(0, $d)
        $parent = [System.IO.Path]::GetDirectoryName($d)
        if ($parent -eq $d) { break }
        $d = $parent
    }
    foreach ($c in $chain) { Add-GitIgnoreDirectory $m $c }
    [pscustomobject]@{ Matcher = $m; RepoRoot = $repoRoot; InRepo = ($repoRoot -ne $ScanRoot -or (Test-Path -LiteralPath $gitDir)) }
}

function Get-SourceFiles {
    param([string]$Root, [string[]]$Ext, [string[]]$Exclude, $GitIgnore)
    $extSet = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($e in $Ext) { [void]$extSet.Add('.' + $e.TrimStart('*').TrimStart('.')) }
    $files = New-Object System.Collections.Generic.List[string]
    $composer = New-Object System.Collections.Generic.List[string]
    $ignoredDirs = 0
    $ignoredFiles = 0
    $stack = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($Root)
    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        if ($GitIgnore) { Add-GitIgnoreDirectory $GitIgnore $dir }
        try { $subDirs = [System.IO.Directory]::GetDirectories($dir) }
        catch { Write-Warning "Cannot read directory '$dir': $($_.Exception.Message)"; continue }
        foreach ($sd in $subDirs) {
            $name = [System.IO.Path]::GetFileName($sd)
            $skip = $false
            foreach ($pat in $Exclude) { if ($name -like $pat) { $skip = $true; break } }
            if ($skip) { continue }
            try {
                if (([System.IO.File]::GetAttributes($sd) -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
            }
            catch { continue }
            if ($GitIgnore -and (Test-GitIgnored $GitIgnore $sd $true)) { $ignoredDirs++; continue }
            $stack.Push($sd)
        }
        try { $dirFiles = [System.IO.Directory]::GetFiles($dir) } catch { continue }
        foreach ($f in $dirFiles) {
            $isPhp = $extSet.Contains([System.IO.Path]::GetExtension($f))
            $isComposer = (-not $isPhp) -and ([System.IO.Path]::GetFileName($f) -eq 'composer.json')
            if (-not ($isPhp -or $isComposer)) { continue }
            if ($GitIgnore -and (Test-GitIgnored $GitIgnore $f $false)) { $ignoredFiles++; continue }
            if ($isPhp) { $files.Add($f) } else { $composer.Add($f) }
        }
    }
    $files.Sort([System.StringComparer]::OrdinalIgnoreCase)
    [pscustomobject]@{ Files = $files; Composer = $composer; IgnoredDirs = $ignoredDirs; IgnoredFiles = $ignoredFiles }
}

function Test-PhpConstraint([string]$Constraint, [version]$Target) {
    # Very small Composer constraint evaluator: returns $true if some patch release of $Target satisfies it.
    $low = New-Object version($Target.Major, $Target.Minor, 0)
    $high = New-Object version($Target.Major, $Target.Minor, 9999)
    foreach ($orPart in ($Constraint -split '\|\|?')) {
        $norm = ($orPart.Trim() -replace '(>=|<=|!=|>|<|\^|~|=)\s+', '$1')
        $tokens = @($norm -split '[\s,]+' | Where-Object { $_ })
        if ($tokens.Count -eq 0) { continue }
        $ok = $true
        foreach ($t in $tokens) {
            if ($t -eq '*') { continue }
            $m = [regex]::Match($t, '^(>=|<=|!=|>|<|\^|~|=)?v?(\d+)(?:\.(\d+|\*|x))?(?:\.(\d+|\*|x))?')
            if (-not $m.Success) { continue }
            $op = $m.Groups[1].Value
            $maj = [int]$m.Groups[2].Value
            $minRaw = $m.Groups[3].Value; $patRaw = $m.Groups[4].Value
            $minWild = ($minRaw -eq '' -or $minRaw -eq '*' -or $minRaw -eq 'x')
            $min = 0; if (-not $minWild) { $min = [int]$minRaw }
            $pat = 0; if ($patRaw -match '^\d+$') { $pat = [int]$patRaw }
            $v = New-Object version($maj, $min, $pat)
            switch ($op) {
                '>=' { if (-not ($high -ge $v)) { $ok = $false } }
                '>' { if (-not ($high -gt $v)) { $ok = $false } }
                '<' { if (-not ($low -lt $v)) { $ok = $false } }
                '<=' { if (-not ($low -le $v)) { $ok = $false } }
                '!=' { }
                '^' { if ($Target.Major -ne $maj -or $high -lt $v) { $ok = $false } }
                '~' {
                    if ($patRaw -ne '') { if ($Target.Major -ne $maj -or $Target.Minor -ne $min) { $ok = $false } }
                    elseif ($Target.Major -ne $maj -or $high -lt $v) { $ok = $false }
                }
                default {
                    if ($Target.Major -ne $maj) { $ok = $false }
                    elseif (-not $minWild -and $Target.Minor -ne $min) { $ok = $false }
                }
            }
            if (-not $ok) { break }
        }
        if ($ok) { return $true }
    }
    return $false
}

function Get-ComposerFindings {
    param([string]$File, [string]$Root)
    $out = New-Object System.Collections.Generic.List[object]
    try { $text = [System.IO.File]::ReadAllText($File) } catch { return $out }
    try { $json = $text | ConvertFrom-Json -ErrorAction Stop } catch { Write-Warning "Cannot parse $File"; return $out }
    $lines = $text -split "`n"
    $rel = Get-RelativePath $File $Root
    $findLine = {
        param($needle)
        for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i].IndexOf($needle, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { return ($i + 1) } }
        return 1
    }

    $deps = [ordered]@{}
    foreach ($sec in 'require', 'require-dev') {
        $node = $json.$sec
        if ($node) { foreach ($p in $node.PSObject.Properties) { $deps[$p.Name] = [string]$p.Value } }
    }

    if ($deps.Contains('php')) {
        $c = $deps['php']
        if (-not (Test-PhpConstraint $c $target)) {
            $ln = & $findLine '"php"'
            $out.Add((New-Finding $rel $ln 1 'Medium' 'Configuration' 'COMPOSER-PHP-CONSTRAINT' "composer.json PHP constraint '$c' does not allow PHP $TargetVersion" 'Configuration' "Update the constraint, e.g. `"php`": `">=$TargetVersion`", and run composer update" $c $lines[$ln - 1].Trim()))
        }
    }
    $platform = $null
    if ($json.config -and $json.config.platform) { $platform = $json.config.platform.php }
    if ($platform) {
        $pv = $null
        if ([version]::TryParse(($platform -replace '^(\d+\.\d+).*$', '$1'), [ref]$pv) -and $pv -lt $target) {
            $ln = & $findLine '"platform"'
            $out.Add((New-Finding $rel $ln 1 'Medium' 'Configuration' 'COMPOSER-PLATFORM-PHP' "config.platform.php is pinned to $platform (dependencies are resolved for that version)" 'Configuration' "Raise config.platform.php to $TargetVersion and run composer update" $platform $lines[$ln - 1].Trim()))
        }
    }

    foreach ($name in $deps.Keys) {
        $sev = $null; $issue = $null; $fix = $null
        if ($name -eq 'dshafik/php7-mysql-shim') { $sev = 'High'; $issue = 'mysql_* shim layered on mysqli'; $fix = 'Migrate mysql_* calls to mysqli/PDO prepared statements, then remove the package' }
        elseif ($name -eq 'phpseclib/mcrypt_compat') { $sev = 'High'; $issue = 'mcrypt polyfill in use'; $fix = 'Migrate to openssl_* or sodium_*; keep only to decrypt legacy data' }
        elseif ($name -eq 'paragonie/random_compat') { $sev = 'Low'; $issue = 'random_bytes()/random_int() polyfill (native since PHP 7.0)'; $fix = 'Remove the package (or require ^9.99 which is empty)' }
        elseif ($name -eq 'ircmaxell/password-compat') { $sev = 'Low'; $issue = 'password_hash() polyfill (native since PHP 5.5)'; $fix = 'Remove the package' }
        elseif ($name -eq 'ralouphie/getallheaders') { $sev = 'Info'; $issue = 'getallheaders() polyfill'; $fix = 'Native in all SAPIs since PHP 7.3; remove if not needed by other packages' }
        elseif ($name -match '^symfony/polyfill-php(\d)(\d)$') {
            $pv = New-Object version([int]$Matches[1], [int]$Matches[2])
            if ($pv -le $target) { $sev = 'Low'; $issue = "Polyfill for PHP $pv features"; $fix = "Not needed on PHP $TargetVersion; remove it (or add it to `"replace`" in the root composer.json)" }
        }
        elseif ($name -match '^symfony/polyfill-(mbstring|iconv|ctype|intl-\w+|apcu|uuid)$') { $sev = 'Info'; $issue = "Polyfill for the $($Matches[1]) extension"; $fix = 'Install the native PHP extension for better performance' }
        elseif ($name -match '(?i)(mysql|mcrypt|ereg).*(shim|compat|polyfill)|(shim|compat|polyfill).*(mysql|mcrypt|ereg)') { $sev = 'High'; $issue = 'Package looks like a compatibility layer for a removed extension'; $fix = 'Migrate to the modern API and remove the package' }
        if ($sev) {
            $ln = & $findLine ('"' + $name + '"')
            $out.Add((New-Finding $rel $ln 1 $sev 'Compatibility Layer' 'COMPOSER-COMPAT-PACKAGE' "$issue ($name)" 'Compatibility layer' $fix $name $lines[$ln - 1].Trim()))
        }
    }
    return $out
}

function Write-HtmlReport {
    param($Findings, [string]$OutFile, $Meta)
    $enc = { param($s) if ($null -eq $s) { '' } else { [System.Net.WebUtility]::HtmlEncode([string]$s) } }
    $sevOrder = 'Critical', 'High', 'Medium', 'Low', 'Info'
    $sb = New-Object System.Text.StringBuilder

    $bySev = @{}; foreach ($s in $sevOrder) { $bySev[$s] = 0 }
    foreach ($f in $Findings) { $bySev[$f.Severity]++ }

    [void]$sb.Append(@'
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>PHP Upgrade Scan</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--fg:#1f2328;--muted:#656d76;--line:#d8dee4;--crit:#b42318;--high:#c4320a;--med:#a15c07;--low:#1d4ed8;--info:#57606a;--mark:#fff1a8}
@media (prefers-color-scheme: dark){:root{--bg:#0d1117;--card:#161b22;--fg:#e6edf3;--muted:#8d96a0;--line:#30363d;--crit:#ff7b72;--high:#ffa657;--med:#e3b341;--low:#79c0ff;--info:#8d96a0;--mark:#5a4b00}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 -apple-system,"Segoe UI",Roboto,Arial,sans-serif}
header{padding:24px 24px 8px}h1{margin:0 0 4px;font-size:22px}h2{font-size:16px;margin:28px 0 10px}
.meta{color:var(--muted);font-size:13px}.meta b{color:var(--fg);font-weight:600}
main{padding:0 24px 40px}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:10px;margin-top:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px}
.card .n{font-size:24px;font-weight:700}.card .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.card.Critical .n{color:var(--crit)}.card.High .n{color:var(--high)}.card.Medium .n{color:var(--med)}.card.Low .n{color:var(--low)}.card.Info .n{color:var(--info)}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:20px}@media(max-width:1000px){.grid2{grid-template-columns:1fr}}
table{border-collapse:collapse;width:100%;background:var(--card);border:1px solid var(--line);border-radius:8px;overflow:hidden}
th,td{padding:7px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{background:var(--bg);font-size:12px;text-transform:uppercase;letter-spacing:.03em;color:var(--muted);white-space:nowrap}
th[data-k]{cursor:pointer}th[data-k]:hover{color:var(--fg)}
td.num{text-align:right;font-variant-numeric:tabular-nums}
.sev{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;font-weight:600;color:#fff;white-space:nowrap}
.sev.Critical{background:var(--crit)}.sev.High{background:var(--high)}.sev.Medium{background:var(--med)}.sev.Low{background:var(--low)}.sev.Info{background:var(--info)}
@media (prefers-color-scheme: dark){.sev{color:#0d1117}}
code{font:12px/1.4 Consolas,"Cascadia Mono",Menlo,monospace;white-space:pre-wrap;word-break:break-all}
mark{background:var(--mark);color:inherit;border-radius:2px}
td.file{word-break:break-all;font-size:13px}td.fix{color:var(--fg)}td.issue{min-width:220px}td.fix{min-width:220px}
.small{color:var(--muted);font-size:12px}
.filters{display:flex;flex-wrap:wrap;gap:14px;align-items:center;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px;margin-bottom:10px;position:sticky;top:0;z-index:2}
.filters input[type=search]{flex:1;min-width:220px;padding:6px 10px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg)}
.filters select{padding:5px 8px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg)}
.filters label{white-space:nowrap;font-size:13px}
a.ff{color:inherit;text-decoration:none;border-bottom:1px dotted var(--muted)}a.ff:hover{color:var(--low)}
.wrap{overflow-x:auto}
</style></head><body>
'@)
    [void]$sb.Append('<header><h1>PHP Upgrade Scan</h1><div class="meta">')
    [void]$sb.AppendFormat('Scanned <b>{0}</b> &middot; target PHP <b>{1}</b> &middot; {2} &middot; {3} files in {4:N1}s',
        (& $enc $Meta.Root), (& $enc $Meta.Target), (& $enc $Meta.Date), $Meta.FileCount, $Meta.Seconds)
    if ($Meta.GitIgnore) { [void]$sb.AppendFormat('<br>.gitignore honoured: {0}', (& $enc $Meta.GitIgnore)) }
    [void]$sb.Append('</div></header><main><div class="cards">')
    [void]$sb.AppendFormat('<div class="card"><div class="n">{0}</div><div class="l">Findings</div></div>', $Findings.Count)
    [void]$sb.AppendFormat('<div class="card"><div class="n">{0}</div><div class="l">Files affected</div></div>', $Meta.FilesWithIssues)
    foreach ($s in $sevOrder) { [void]$sb.AppendFormat('<div class="card {0}"><div class="n">{1}</div><div class="l">{0}</div></div>', $s, $bySev[$s]) }
    [void]$sb.Append('</div>')

    # Category + top files
    $cats = $Findings | Group-Object Category | Sort-Object Count -Descending
    [void]$sb.Append('<div class="grid2"><section><h2>By category</h2><div class="wrap"><table><thead><tr><th>Category</th>')
    foreach ($s in $sevOrder) { [void]$sb.AppendFormat('<th class="num">{0}</th>', $s) }
    [void]$sb.Append('<th class="num">Total</th></tr></thead><tbody>')
    foreach ($c in $cats) {
        [void]$sb.AppendFormat('<tr><td>{0}</td>', (& $enc $c.Name))
        $cs = @{}; foreach ($s in $sevOrder) { $cs[$s] = 0 }; foreach ($f in $c.Group) { $cs[$f.Severity]++ }
        foreach ($s in $sevOrder) { if ($cs[$s]) { [void]$sb.AppendFormat('<td class="num">{0}</td>', $cs[$s]) } else { [void]$sb.Append('<td class="num small">-</td>') } }
        [void]$sb.AppendFormat('<td class="num"><b>{0}</b></td></tr>', $c.Count)
    }
    [void]$sb.Append('</tbody></table></div></section>')

    $weights = @{ Critical = 1000; High = 100; Medium = 10; Low = 1; Info = 0 }
    $topFiles = $Findings | Group-Object File | ForEach-Object {
        $score = 0; $cs = @{}; foreach ($s in $sevOrder) { $cs[$s] = 0 }
        foreach ($f in $_.Group) { $score += $weights[$f.Severity]; $cs[$f.Severity]++ }
        [pscustomobject]@{ File = $_.Name; Count = $_.Count; Score = $score; S = $cs }
    } | Sort-Object Score, Count -Descending | Select-Object -First 25
    [void]$sb.Append('<section><h2>Most affected files</h2><div class="wrap"><table><thead><tr><th>File</th><th class="num">Crit</th><th class="num">High</th><th class="num">Med</th><th class="num">Low</th><th class="num">Info</th></tr></thead><tbody>')
    foreach ($t in $topFiles) {
        [void]$sb.AppendFormat('<tr><td class="file"><a href="#" class="ff" data-f="{0}">{0}</a></td>', (& $enc $t.File))
        foreach ($s in $sevOrder) { if ($t.S[$s]) { [void]$sb.AppendFormat('<td class="num">{0}</td>', $t.S[$s]) } else { [void]$sb.Append('<td class="num small">-</td>') } }
        [void]$sb.Append('</tr>')
    }
    [void]$sb.Append('</tbody></table></div></section></div>')

    # Findings table
    [void]$sb.Append('<h2>Findings</h2><div class="filters"><input type="search" id="q" placeholder="Filter by file, function, text...">')
    foreach ($s in $sevOrder) { [void]$sb.AppendFormat('<label><input type="checkbox" class="sevf" value="{0}" checked> {0}</label>', $s) }
    [void]$sb.Append('<select id="cat"><option value="">All categories</option>')
    foreach ($c in ($cats | Sort-Object Name)) { [void]$sb.AppendFormat('<option>{0}</option>', (& $enc $c.Name)) }
    [void]$sb.Append('</select><span class="small"><b id="shown">0</b> shown</span></div>')
    [void]$sb.Append('<div class="wrap"><table id="findings"><thead><tr><th data-k="sev">Severity</th><th data-k="txt">File</th><th data-k="num" class="num">Line</th><th data-k="txt">Category</th><th data-k="txt">Issue</th><th>Code</th><th>Suggested fix</th><th data-k="txt">PHP</th></tr></thead><tbody>')
    foreach ($f in $Findings) {
        $codeHtml = & $enc $f.Code
        if ($f.Match -and $f.Code) {
            $idx = $f.Code.IndexOf($f.Match)
            if ($idx -ge 0) {
                $codeHtml = (& $enc $f.Code.Substring(0, $idx)) + '<mark>' + (& $enc $f.Match) + '</mark>' + (& $enc $f.Code.Substring($idx + $f.Match.Length))
            }
        }
        [void]$sb.AppendFormat('<tr data-sev="{0}" data-rank="{1}" data-cat="{2}"><td><span class="sev {0}" title="{3}">{0}</span></td><td class="file">{4}</td><td class="num">{5}</td><td>{2}</td><td class="issue">{6}<div class="small">{3}</div></td><td><code>{7}</code></td><td class="fix">{8}</td><td class="small">{9}</td></tr>',
            $f.Severity, $SeverityRank[$f.Severity], (& $enc $f.Category), (& $enc $f.RuleId), (& $enc $f.File), $f.Line,
            (& $enc $f.Issue), $codeHtml, (& $enc $f.SuggestedFix), (& $enc $f.PhpVersion))
    }
    [void]$sb.Append('</tbody></table></div>')
    [void]$sb.Append('<p class="small">Pattern-based static scan: results are indicative. Suppress a line with a <code>phpscan:ignore</code> comment, or a file with <code>phpscan:ignore-file</code>.</p></main>')
    [void]$sb.Append(@'
<script>
(function(){
  var tbody=document.querySelector('#findings tbody'); if(!tbody) return;
  var rows=Array.prototype.slice.call(tbody.rows);
  rows.forEach(function(r){ r._t=r.textContent.toLowerCase(); });
  var q=document.getElementById('q'), cat=document.getElementById('cat'), shown=document.getElementById('shown');
  var sevs=document.querySelectorAll('input.sevf');
  function apply(){
    var term=q.value.toLowerCase().trim(), c=cat.value, on={}, n=0, i;
    for(i=0;i<sevs.length;i++){ if(sevs[i].checked) on[sevs[i].value]=1; }
    for(i=0;i<rows.length;i++){
      var r=rows[i];
      var ok=on[r.getAttribute('data-sev')] && (!c || r.getAttribute('data-cat')===c) && (!term || r._t.indexOf(term)>=0);
      r.style.display=ok?'':'none'; if(ok) n++;
    }
    shown.textContent=n;
  }
  var timer; q.addEventListener('input',function(){ clearTimeout(timer); timer=setTimeout(apply,150); });
  cat.addEventListener('change',apply);
  for(var i=0;i<sevs.length;i++) sevs[i].addEventListener('change',apply);
  var dir={};
  Array.prototype.forEach.call(document.querySelectorAll('#findings th[data-k]'),function(th){
    th.addEventListener('click',function(){
      var k=th.getAttribute('data-k'), col=th.cellIndex, key=k+col; dir[key]=dir[key]===1?-1:1; var d=dir[key];
      rows.sort(function(a,b){
        var x,y;
        if(k==='sev'){ x=+b.getAttribute('data-rank'); y=+a.getAttribute('data-rank'); }
        else if(k==='num'){ x=+a.cells[col].textContent; y=+b.cells[col].textContent; }
        else { x=a.cells[col].textContent.toLowerCase(); y=b.cells[col].textContent.toLowerCase(); }
        return x<y?-d:(x>y?d:0);
      });
      var frag=document.createDocumentFragment(); rows.forEach(function(r){ frag.appendChild(r); }); tbody.appendChild(frag);
    });
  });
  Array.prototype.forEach.call(document.querySelectorAll('a.ff'),function(a){
    a.addEventListener('click',function(e){ e.preventDefault(); q.value=a.getAttribute('data-f'); apply(); document.getElementById('findings').scrollIntoView({behavior:'smooth'}); });
  });
  apply();
})();
</script></body></html>
'@)
    [System.IO.File]::WriteAllText($OutFile, $sb.ToString(), (New-Object System.Text.UTF8Encoding($false)))
}
#endregion

#region ---------------------------------------------------------------- Resolve input / output
if ($Browse) {
    Add-Type -AssemblyName System.Windows.Forms
    $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
    $dlg.Description = 'Select the folder containing the PHP code to scan'
    $start = Resolve-Path -LiteralPath $Path -ErrorAction SilentlyContinue
    if ($start) { $dlg.SelectedPath = $start.ProviderPath }
    if ($dlg.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { Write-Warning 'No folder selected.'; return }
    $Path = $dlg.SelectedPath
}

if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
    Write-Error "Directory not found: $Path"
    return
}
$root = (Resolve-Path -LiteralPath $Path).ProviderPath.TrimEnd('\', '/')
if ($root -match '^[A-Za-z]:$') { $root += '\' }

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
if ([string]::IsNullOrEmpty($OutputPath)) {
    $basePath = Join-Path (Get-Location).ProviderPath "PHP-Upgrade-Report_$stamp"
}
elseif (Test-Path -LiteralPath $OutputPath -PathType Container) {
    $basePath = Join-Path (Resolve-Path -LiteralPath $OutputPath).ProviderPath "PHP-Upgrade-Report_$stamp"
}
else {
    $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
    $basePath = Join-Path ([System.IO.Path]::GetDirectoryName($full)) ([System.IO.Path]::GetFileNameWithoutExtension($full))
}
#endregion

#region ---------------------------------------------------------------- Scan
Write-Host "Scanning $root for PHP $TargetVersion compatibility issues..." -ForegroundColor Cyan
$gitIgnoreMatcher = $null
$gitIgnoreNote = ''
if ($NoGitIgnore -and $UseGitIgnore) {
    Write-Warning '-UseGitIgnore and -NoGitIgnore were both given; -NoGitIgnore wins and .gitignore rules are not applied.'
}
if (-not $NoGitIgnore) {
    $gi = New-GitIgnoreMatcher -ScanRoot $root
    $gitIgnoreMatcher = $gi.Matcher
    if ($gi.RepoRoot -ne $root) { Write-Host "Honouring .gitignore rules (repository root: $($gi.RepoRoot))" }
    else { Write-Host 'Honouring .gitignore rules' }
}
$src = Get-SourceFiles -Root $root -Ext $Extensions -Exclude $ExcludeDirectory -GitIgnore $gitIgnoreMatcher
$files = $src.Files
$total = $files.Count
if ($gitIgnoreMatcher) {
    $gitIgnoreNote = '{0} pattern(s) from {1} ignore file(s); {2} folder(s) and {3} file(s) excluded' -f `
        $gitIgnoreMatcher.PatternCount, $gitIgnoreMatcher.LoadedFiles.Count, $src.IgnoredDirs, $src.IgnoredFiles
    if ($gitIgnoreMatcher.LoadedFiles.Count -eq 0) {
        $gitIgnoreNote = ''
        Write-Host '.gitignore: no ignore files found; nothing excluded'
    }
    else { Write-Host ".gitignore: $gitIgnoreNote (use -NoGitIgnore to scan ignored files)" }
}
Write-Host ("Found {0} PHP file(s); {1} rule(s) active." -f $total, $Rules.Count)

$findings = New-Object System.Collections.Generic.List[object]
$maxBytes = [int64]$MaxFileSizeMB * 1MB
$filesScanned = 0
$skipped = 0
$progressEvery = [Math]::Max(1, [int]($total / 200))
$interp = [char]1

for ($fi = 0; $fi -lt $total; $fi++) {
    $filePath = $files[$fi]
    $rel = Get-RelativePath $filePath $root
    if (($fi % $progressEvery) -eq 0) {
        Write-Progress -Activity 'Scanning PHP files' -Status $rel -PercentComplete ([int](100 * $fi / [Math]::Max(1, $total)))
    }

    try {
        $len = (New-Object System.IO.FileInfo($filePath)).Length
        if ($len -gt $maxBytes) { Write-Warning "Skipping $rel ($([int]($len / 1MB)) MB > $MaxFileSizeMB MB)"; $skipped++; continue }
        $raw = [System.IO.File]::ReadAllText($filePath)
    }
    catch { Write-Warning "Cannot read ${rel}: $($_.Exception.Message)"; $skipped++; continue }
    $filesScanned++

    if ($raw.IndexOf('<?') -lt 0 -and $raw.IndexOf('<%') -lt 0 -and $raw.IndexOf('<script', [System.StringComparison]::OrdinalIgnoreCase) -lt 0) { continue }
    if ($raw.IndexOf('phpscan:ignore-file', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { continue }

    $stripped = Get-PhpStrippedText $raw
    $code = $stripped[0]
    $bare = $stripped[1]
    $starts = Get-LineStarts $raw
    $fileHits = @{}    # "line|group" -> finding (keeps the most severe per line and group)
    $lineCache = @{}

    foreach ($rule in $Rules) {
        switch ($rule.Scope) {
            'Code' { $text = $bare }
            'Raw' { $text = $raw }
            default { $text = $code }
        }
        $ms = $rule.Regex.Matches($text)
        if ($ms.Count -eq 0) { continue }
        foreach ($m in $ms) {
            if ($rule.Scope -eq 'StringsOnly' -and $bare[$m.Index] -ne $interp) { continue }
            # inline equivalent of Get-LineNumber (hot path; function calls are slow in PS 5.1)
            $line = [Array]::BinarySearch($starts, $m.Index)
            if ($line -ge 0) { $line++ } else { $line = -bnot $line }
            $lineText = $lineCache[$line]
            if ($null -eq $lineText) {
                # inline equivalent of Get-LineText
                if ($line -lt $starts.Length) { $lineEnd = $starts[$line] } else { $lineEnd = $raw.Length }
                $lineText = $raw.Substring($starts[$line - 1], $lineEnd - $starts[$line - 1]).TrimEnd([char]13, [char]10)
                $lineCache[$line] = $lineText
            }
            if ($lineText.IndexOf('phpscan:ignore', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { continue }
            if ($rule.Suppress -and $rule.Suppress.IsMatch($lineText)) { continue }

            if ($rule.IsFunction) {
                $fn = $m.Groups['fn'].Value
                $info = Resolve-FuncInfo $fn
                if (-not $info -or -not (Test-VersionInScope $info.Version)) { continue }
                $sev = $info.Severity
                $cat = $info.Category
                $ver = Get-StatusText $info.Status $info.Version
                switch ($info.Status) {
                    'Removed' { $issue = "$fn() was removed in PHP $($info.Version)" }
                    'Unbundled' { $issue = "$fn() belongs to an extension no longer bundled with PHP $($info.Version) (PECL only)" }
                    default { $issue = "$fn() is deprecated as of PHP $($info.Version)" }
                }
                $fix = $info.Fix
                $ruleId = 'FN-' + $fn.ToLowerInvariant()
                $group = 'fn:' + $fn.ToLowerInvariant()
            }
            else {
                $sev = $rule.Severity; $cat = $rule.Category; $ver = $rule.PhpVersion
                $issue = $rule.Issue; $fix = $rule.Fix; $ruleId = $rule.Id; $group = $rule.Group
            }
            if ($SeverityRank[$sev] -lt $minRank) { continue }

            $matchText = $raw.Substring($m.Index, $m.Length)
            $nl = $matchText.IndexOfAny([char[]]"`r`n")
            if ($nl -ge 0) { $matchText = $matchText.Substring(0, $nl) }
            $matchText = $matchText.Trim()
            $snippet = $lineText.Trim()
            if ($snippet.Length -gt 300) { $snippet = $snippet.Substring(0, 297) + '...' }
            $col = $m.Index - $starts[$line - 1] + 1

            $key = "$line|$group"
            $existing = $fileHits[$key]
            if ($existing -and $SeverityRank[$existing.Severity] -ge $SeverityRank[$sev]) { continue }
            $fileHits[$key] = New-Finding $rel $line $col $sev $cat $ruleId $issue $ver $fix $matchText $snippet
        }
    }

    # PHP 4 style constructors (method named like its class, no __construct, no namespace)
    if ((Test-VersionInScope '7.0') -and -not $reNamespace.IsMatch($bare) -and -not $reConstruct.IsMatch($bare)) {
        foreach ($cm in $reClassDecl.Matches($bare)) {
            $cname = $cm.Groups['name'].Value
            $reCtor = New-Object System.Text.RegularExpressions.Regex(('(?<![\w$>:])function\s+&?\s*' + [regex]::Escape($cname) + '\s*\('), $ciOptions)
            $mm = $reCtor.Match($bare, $cm.Index + $cm.Length)
            if (-not $mm.Success) { continue }
            $line = Get-LineNumber $starts $mm.Index
            $lineText = Get-LineText $raw $starts $line
            if ($lineText.IndexOf('phpscan:ignore', [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { continue }
            if ($target -ge [version]'8.0') { $sev = 'Critical'; $ver = 'Removed in PHP 8.0' } else { $sev = 'Medium'; $ver = 'Deprecated in PHP 7.0' }
            if ($SeverityRank[$sev] -lt $minRank) { continue }
            $fileHits["$line|php4ctor"] = New-Finding $rel $line ($mm.Index - $starts[$line - 1] + 1) $sev 'Removed Syntax' 'SYN-PHP4-CONSTRUCTOR' `
                ('PHP 4 style constructor {0}::{0}() - no longer called as the constructor in PHP 8.0' -f $cname) $ver `
                ('Rename it to __construct() (keep a {0}() wrapper calling $this->__construct() if other code calls it)' -f $cname) `
                $raw.Substring($mm.Index, $mm.Length).Trim() $lineText.Trim()
        }
    }

    if ($fileHits.Count -gt 0) {
        foreach ($h in ($fileHits.Values | Sort-Object Line, Column)) { $findings.Add($h) }
    }
}
Write-Progress -Activity 'Scanning PHP files' -Completed

if (-not $NoComposerCheck) {
    foreach ($cf in $src.Composer) {
        foreach ($f in (Get-ComposerFindings -File $cf -Root $root)) {
            if ($SeverityRank[$f.Severity] -ge $minRank) { $findings.Add($f) }
        }
    }
}

$sorted = @($findings | Sort-Object @{ Expression = { $SeverityRank[$_.Severity] }; Descending = $true }, File, Line, Column)
$elapsed = ((Get-Date) - $scanStart).TotalSeconds
#endregion

#region ---------------------------------------------------------------- Output
$written = @()
if ($Format -eq 'Csv' -or $Format -eq 'Both') {
    $csvPath = "$basePath.csv"
    $sorted | Select-Object Severity, Category, File, Line, Column, RuleId, Issue, PhpVersion, SuggestedFix, Match, Code |
        Export-Csv -LiteralPath $csvPath -NoTypeInformation -Encoding UTF8
    if ($sorted.Count -eq 0) {
        # Export-Csv writes nothing for an empty set; still produce a header row
        '"Severity","Category","File","Line","Column","RuleId","Issue","PhpVersion","SuggestedFix","Match","Code"' |
            Set-Content -LiteralPath $csvPath -Encoding UTF8
    }
    $written += $csvPath
}
$htmlPath = $null
if ($Format -eq 'Html' -or $Format -eq 'Both') {
    $htmlPath = "$basePath.html"
    $meta = [pscustomobject]@{
        Root            = $root
        Target          = $TargetVersion
        Date            = (Get-Date -Format 'yyyy-MM-dd HH:mm')
        FileCount       = $filesScanned
        Seconds         = $elapsed
        FilesWithIssues = @($sorted | Select-Object -ExpandProperty File -Unique).Count
        GitIgnore       = $gitIgnoreNote
    }
    Write-HtmlReport -Findings $sorted -OutFile $htmlPath -Meta $meta
    $written += $htmlPath
}

$colors = @{ Critical = 'Red'; High = 'DarkYellow'; Medium = 'Yellow'; Low = 'Cyan'; Info = 'Gray' }
Write-Host ''
Write-Host ("Scan complete in {0:N1}s - {1} file(s) scanned, {2} skipped, {3} finding(s)" -f $elapsed, $filesScanned, $skipped, $sorted.Count) -ForegroundColor Green
foreach ($s in 'Critical', 'High', 'Medium', 'Low', 'Info') {
    $n = @($sorted | Where-Object { $_.Severity -eq $s }).Count
    Write-Host ('  {0,-9} {1,6}' -f $s, $n) -ForegroundColor $colors[$s]
}
foreach ($w in $written) { Write-Host "Report: $w" }

if ($OpenReport -and $htmlPath) { Invoke-Item -LiteralPath $htmlPath }
if ($PassThru) { $sorted }

if ($FailOn -ne 'None') {
    $failRank = $SeverityRank[$FailOn]
    if (@($sorted | Where-Object { $SeverityRank[$_.Severity] -ge $failRank }).Count -gt 0) { exit 2 }
}
#endregion
