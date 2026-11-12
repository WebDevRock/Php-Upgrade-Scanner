# Invoke-PhpUpgradeScan.ps1

A PowerShell script that scans a PHP codebase for code that will break, or start emitting deprecation warnings, when you upgrade PHP. It checks the PHP 5.x through 8.5 changes and writes an HTML and/or CSV report. Each finding has a file, line, severity and suggested fix.

It is a fast static, pattern-based scan. It doesn't run your code and it doesn't need PHP, Git or any module installed.

## Contents

- [Requirements](#requirements)
  - [Security notes](#security-notes)
- [Quick start](#quick-start)
- [Parameters](#parameters)
- [Examples](#examples)
- [Output](#output)
- [Severity levels](#severity-levels)
- [Rules checked](#rules-checked)
- [.gitignore handling](#gitignore-handling)
- [Suppressing findings](#suppressing-findings)
- [Testing](#testing)
- [Limitations](#limitations)

## Requirements

- Windows PowerShell **5.1** or PowerShell **7+** (tested on Windows with both). Nothing else needs installing.
- **Full Language mode** (the PowerShell default). See [Security notes](#security-notes).
- `-Browse` needs Windows, because it uses a Windows Forms folder picker.

### Security notes

- **No code is compiled.** The script is plain PowerShell. It doesn't use `Add-Type` with C# code, doesn't start `csc.exe` and writes no temporary DLLs. Earlier versions compiled a C# helper at startup, and that has been rewritten in PowerShell. It only uses .NET classes that ship with PowerShell itself, such as regular expressions and collections.
- **The only `Add-Type`** is `Add-Type -AssemblyName System.Windows.Forms`, which loads a built-in Windows component without compiling anything. It only runs when you use `-Browse`.
- **Constrained Language Mode is not supported.** AppLocker or WDAC policies can enforce this mode, and it blocks the generic .NET collections the script uses. To check, run `$ExecutionContext.SessionState.LanguageMode`: if it says `FullLanguage`, the script will run.
- **It is read-only.** It only reads source files and writes the report files you ask for. It makes no network calls and doesn't run PHP or Git. The only external program it can start is your default browser, to open the HTML report, and only with `-OpenReport`.

If your execution policy blocks the script, either unblock it once or run it with a bypass:

```powershell
Unblock-File .\Invoke-PhpUpgradeScan.ps1
# or
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-PhpUpgradeScan.ps1 -Path C:\sites\app
```

## Quick start

```powershell
cd C:\sites\my-app
C:\tools\Invoke-PhpUpgradeScan.ps1 -OpenReport
```

This scans the current directory against PHP 8.5, skips anything Git ignores, and writes
`PHP-Upgrade-Report_<timestamp>.html` and `.csv` into the current directory. The HTML report then opens.

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-Path` | string (position 0) | `.` (current directory) | Directory to scan recursively. |
| `-Browse` | switch | off | Show a folder picker to choose the directory. `-Path` sets the initial folder. |
| `-Format` | `Html` \| `Csv` \| `Both` | `Both` | Which report(s) to write. |
| `-OutputPath` | string | `.\PHP-Upgrade-Report_<timestamp>` | Report file name. Any extension is replaced with `.html`/`.csv`. If it is an existing directory, timestamped reports are written inside it. |
| `-TargetVersion` | string `X.Y` | `8.5` | The PHP version you are upgrading to. Rules for changes made after this version are skipped. For example, `7.4` hides PHP 8 issues. |
| `-MinSeverity` | `Info` \| `Low` \| `Medium` \| `High` \| `Critical` | `Info` | Lowest severity to report. |
| `-Extensions` | string[] | `.php .php3 .php4 .php5 .php7 .phtml .inc` | File extensions treated as PHP. |
| `-ExcludeDirectory` | string[] | `vendor node_modules .git .svn .hg .idea .vscode` | Directory names (wildcards allowed) that are never entered. Pass `@()` to scan everything. |
| `-NoGitIgnore` | switch | off | Scan files even if `.gitignore` excludes them. By default ignored files are skipped. See [.gitignore handling](#gitignore-handling). |
| `-MaxFileSizeMB` | int (1-1024) | `10` | Files larger than this are skipped with a warning, for example minified or generated bundles. |
| `-NoComposerCheck` | switch | off | Don't inspect `composer.json` files. |
| `-FailOn` | `None` \| `Info` \| `Low` \| `Medium` \| `High` \| `Critical` | `None` | Exit with code **2** if any finding is at or above this severity. Useful for CI. |
| `-PassThru` | switch | off | Also write the finding objects to the pipeline. |
| `-OpenReport` | switch | off | Open the HTML report when the scan finishes. |

`-UseGitIgnore` is still accepted for backward compatibility but does nothing, because honouring `.gitignore` is now the default.

The full built-in help is available with:

```powershell
Get-Help .\Invoke-PhpUpgradeScan.ps1 -Full
```

## Examples

Scan the current directory with all defaults:

```powershell
.\Invoke-PhpUpgradeScan.ps1
```

Scan a site for a PHP 8.1 upgrade and open the HTML report:

```powershell
.\Invoke-PhpUpgradeScan.ps1 -Path C:\inetpub\wwwroot\site -TargetVersion 8.1 -Format Html -OpenReport
```

Pick a folder interactively and show only High and Critical issues:

```powershell
.\Invoke-PhpUpgradeScan.ps1 -Browse -MinSeverity High
```

Include third-party code and Git-ignored files:

```powershell
.\Invoke-PhpUpgradeScan.ps1 -ExcludeDirectory @('.git') -NoGitIgnore
```

Write reports to a specific folder:

```powershell
.\Invoke-PhpUpgradeScan.ps1 -Path D:\src\shop -OutputPath D:\reports\
```

Fail a CI build if anything Critical is found:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Invoke-PhpUpgradeScan.ps1 -Path . -Format Csv -FailOn Critical
if ($LASTEXITCODE -eq 2) { throw 'PHP upgrade blockers found' }
```

Work with the results in PowerShell:

```powershell
$f = .\Invoke-PhpUpgradeScan.ps1 -Format Csv -PassThru
$f | Group-Object RuleId | Sort-Object Count -Descending | Select-Object -First 10 Count, Name
$f | Where-Object Category -eq 'Legacy Database' | Format-Table File, Line, Match
```

## Output

### Console

The console shows a summary with the number of files scanned and skipped, counts per severity, the `.gitignore` summary, and the report paths.

### CSV

The CSV is UTF-8 with a BOM so it opens cleanly in Excel. Columns:

| Column | Meaning |
|---|---|
| `Severity` | Critical / High / Medium / Low / Info |
| `Category` | Rule category (see below) |
| `File` | Path relative to the scanned directory |
| `Line`, `Column` | 1-based position of the match |
| `RuleId` | Rule identifier, e.g. `FN-mysql_query`, `COUNT-VARIABLE`, `SYN-CURLY-OFFSET` |
| `Issue` | What is wrong |
| `PhpVersion` | e.g. `Removed in PHP 7.0`, `Deprecated in PHP 8.1` |
| `SuggestedFix` | How to fix it |
| `Match` | The matched source text |
| `Code` | The full source line (trimmed, up to 300 characters) |

### HTML

The HTML report is a single self-contained file that works offline. It contains:

- Summary cards: total findings, files affected, and counts per severity
- A breakdown by category and severity
- The 25 most affected files. Click one to filter the findings table to that file.
- The findings table, with a text search, severity checkboxes, a category filter, sortable columns and the matched code highlighted

It follows the system light/dark theme.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Scan completed (and the `-FailOn` threshold was not reached) |
| 2 | `-FailOn` threshold reached |

## Severity levels

| Severity | Meaning |
|---|---|
| **Critical** | Removed in the target version. Causes a fatal error, parse error or `TypeError`. |
| **High** | Very likely to break or behave differently, or a serious security risk (for example SQL built from variables, or extensions moved to PECL). |
| **Medium** | Deprecated (emits warnings and will be removed later), or a broad check that is likely but not certain to be a problem. |
| **Low** | Minor deprecations, no-op calls, or polyfills that can be removed. |
| **Info** | Modernisation suggestions. |

## Rules checked

### Removed and deprecated functions (`FN-<name>`)

There are about 150 functions plus whole extension families. Each has its own fix suggestion.

| PHP version | Examples |
|---|---|
| Removed 5.x | `session_register`, `session_unregister`, `session_is_registered`, `import_request_variables`, `define_syslog_variables`, `sqlite_*`, `msql_*`, `fbsql_*`, `ifx_*`, `dbase_*` / `ingres_*` (to PECL) |
| Removed 7.0 | `mysql_*`, `mssql_*`, `sybase_*`, `ereg`, `eregi`, `ereg_replace`, `eregi_replace`, `split`, `spliti`, `sql_regcase`, `call_user_method(_array)`, `set_magic_quotes_runtime`, `set_socket_blocking`, `datefmt_set_timezone_id`, `imageps*` |
| Removed 7.2 / 7.4 | `mcrypt_*`, `mdecrypt_generic`, `wddx_*`, `recode*`, `ibase_*` / `fbird_*` (to PECL) |
| Removed 8.0 | `create_function`, `each`, `get_magic_quotes_gpc/runtime`, `money_format`, `hebrevc`, `convert_cyr_string`, `restore_include_path`, `ezmlm_hash`, `fgetss`, `gzgetss`, `image2wbmp`, `jpeg2wbmp`, `png2wbmp`, `read_exif_data`, `gmp_random`, `ldap_sort`, `ldap_control_paged_result(_response)`, `mbereg*`, `mbsplit`, `mbregex_encoding`, `xmlrpc_*` (to PECL) |
| Deprecated 8.0 | `zip_open` / `zip_read` / `zip_entry_*`, `libxml_disable_entity_loader`, `openssl_pkey_free`, `openssl_free_key`, `openssl_x509_free`, old `pg_*` aliases (`pg_numrows`, `pg_errormessage`, ...) |
| Deprecated 8.1 | `strftime`, `gmstrftime`, `strptime`, `date_sunrise`, `date_sunset`, `mhash*`, `odbc_result_all` |
| Deprecated 8.2 / 8.3 | `utf8_encode`, `utf8_decode`, `assert_options` |
| 8.4 | Deprecated: `lcg_value`, `mysqli_ping`, `mysqli_kill`, `mysqli_refresh`. Moved to PECL: `imap_*`, `pspell_*`, `oci*` |
| Deprecated 8.5 | `curl_close`, `curl_share_close`, `finfo_close`, `imagedestroy`, `xml_parser_free` (no-ops) |

Method and static calls with the same name, such as `$collection->each()` or `Str::split()`, namespaced functions, and function declarations are not flagged.

### Unsafe `count()`

`count()` on anything other than an array or `Countable` throws a `TypeError` in PHP 8.0 (it was a warning from 7.2).

| Rule | Severity | Detects |
|---|---|---|
| `COUNT-SCALAR` | Critical | `count("abc")`, `count(5)`, `count(null)` |
| `COUNT-FALSY-SOURCE` | High | `count()` on results that can be `false`/`null`: `json_decode`, `glob`, `file`, `scandir`, `unserialize`, `mysql(i)_fetch_*`, `->fetch*()`, `getimagesize`, `parse_url`, ... |
| `COUNT-SUPERGLOBAL` | High | `count($_POST['ids'])` and similar |
| `COUNT-VARIABLE` | Medium | `count($var)` / `count($this->prop)` that is not guarded on the same line |

The variable and superglobal checks are skipped when the same line shows a guard: `is_countable`, `is_array`, `instanceof Countable`, `(array)` or `?? []`.

### Unsafe `strlen()`

This covers `strlen`, `mb_strlen` and `iconv_strlen`. Passing `null` is deprecated in PHP 8.1, and arrays throw a `TypeError` from 8.0.

| Rule | Severity | Detects |
|---|---|---|
| `STRLEN-SUPERGLOBAL` | High | `strlen($_GET['x'])`: the value may be missing (null) or an array (`?x[]=1`) |
| `STRLEN-NULLABLE-SOURCE` | Medium | `strlen()` on results that can be false/null: `fgets`, `file_get_contents`, `getenv`, `filter_input`, `json_encode`, `preg_replace`, `ob_get_clean`, `*fetch*`, ... |
| `STRLEN-EMPTY-TEST` | Low | `strlen($x) == 0`, `!strlen($x)`, `if (strlen($x))`. Suggests `$x !== ''` |
| `STRLEN-VARIABLE` | Low | `strlen($var)` with no null guard on the line |
| `NULLARG-REQUEST` | Medium | Request values passed straight into string functions: `trim($_POST['x'])`, `htmlspecialchars($_GET['q'])`, `explode(',', $_REQUEST['ids'])`, ... |

These are skipped when the line contains `is_string`, `(string)`, `?? ''`, `isset(`, `!empty(`, `=== null` and similar guards.

### Unsafe `list()`

| Rule | Severity | Detects |
|---|---|---|
| `LIST-EACH` | Critical | `while (list($k, $v) = each($arr))`. Suggests `foreach` |
| `LIST-EMPTY` | Critical | `list() = $x` (fatal error since 7.0) |
| `LIST-APPEND-ORDER` | High | `list($a[], $a[]) = ...`: assignment order changed in 7.0 |
| `LIST-STRING` | High | `list($a, $b) = "ab"`: strings are no longer unpacked |
| `LIST-SHORTFALL` | Medium | `list(...) = explode(...)` / `preg_split` / `fgetcsv` / `fetch*`, ...: too few elements gives "Undefined array key" warnings in PHP 8 |
| `LIST-MODERNISE` | Info | Any other `list()`. Suggests `[$a, $b] = ...` |

### Removed and deprecated syntax

| Rule | Severity | PHP | Detects |
|---|---|---|---|
| `SYN-CURLY-OFFSET` | Critical | removed 8.0 | `$str{0}` |
| `SYN-REAL-CAST` / `SYN-UNSET-CAST` | Critical | removed 8.0 | `(real)`, `(unset)` |
| `SYN-AUTOLOAD` | Critical | removed 8.0 | `function __autoload()` |
| `SYN-PHP-ERRORMSG` | Critical | removed 8.0 | `$php_errormsg` |
| `SYN-PARSE-STR-1ARG` | Critical | removed 8.0 | `parse_str($q)` without a result array |
| `SYN-ASSERT-STRING` | Critical | removed 8.0 | `assert('$x > 0')` |
| `SYN-IMPLODE-ORDER` | Critical | removed 8.0 | `implode($array, ', ')` |
| `SYN-DEFINE-CI` | High | removed 8.0 | `define('X', 1, true)` |
| `SYN-NESTED-TERNARY` | High | removed 8.0 | `$a ? 1 : $b ? 2 : 3` |
| `SYN-PHP4-CONSTRUCTOR` | Critical | removed 8.0 | `class Foo { function Foo() {} }` (only non-namespaced classes without `__construct`) |
| `SYN-RESERVED-CLASS` | Critical | 7.0+ | `class String`, `Object`, `Int`, `Mixed`, `Match`, ... |
| `SYN-GLOBALS-WRITE` | Critical | removed 8.1 | `$GLOBALS = [...]` |
| `SYN-NEW-BYREF` | Critical | removed 7.0 | `$o = &new Foo` |
| `SYN-PREG-E` | Critical | removed 7.0 | `preg_replace('/.../e', ...)` |
| `SYN-RAW-POST-DATA` | Critical | removed 7.0 | `$HTTP_RAW_POST_DATA` |
| `SYN-HTTP-VARS` | Critical | removed 5.4 | `$HTTP_GET_VARS`, `$HTTP_POST_VARS`, ... |
| `SYN-SCRIPT-PHP` | Critical | removed 7.0 | `<script language="php">` |
| `SYN-ASP-TAGS` | Medium | removed 7.0 | `<% ... %>` |
| `SYN-SHORT-OPEN-TAG` | Medium | config | `<?` (depends on `short_open_tag`) |
| `SYN-OPTIONAL-BEFORE-REQUIRED` | Medium | deprecated 8.0 | `function f($a = 1, $b)` |
| `SYN-DOLLAR-BRACE` | Medium | deprecated 8.2 | `"${var}"` inside interpolated strings |
| `SYN-CALLABLE-STRING` | Medium | deprecated 8.2 | `"self::method"`, `['parent', 'm']` |
| `SYN-IMPLICIT-NULLABLE` | Medium | deprecated 8.4 | `function f(Foo $x = null)` |
| `SYN-GET-CLASS-NOARGS` | Low | deprecated 8.3 | `get_class()`, `get_parent_class()` |
| `SYN-USER-ERROR` | Low | deprecated 8.4 | `trigger_error(..., E_USER_ERROR)` |
| `SYN-NONCANONICAL-CAST` | Low | deprecated 8.5 | `(integer)`, `(boolean)`, `(double)`, `(binary)` |
| `VAR-HTTP-RESPONSE-HEADER` | Low | deprecated 8.5 | `$http_response_header` |

### Constants and configuration

| Rule | Severity | Detects |
|---|---|---|
| `CONST-MYSQL` | Critical | `MYSQL_ASSOC`, `MYSQL_NUM`, `MYSQL_BOTH`, `MYSQL_CLIENT_*` |
| `CONST-FILTER-FLAGS` | High | `FILTER_FLAG_SCHEME_REQUIRED`, `FILTER_FLAG_HOST_REQUIRED` (removed 8.0) |
| `CONST-INTL-IDNA-2003` | High | `INTL_IDNA_VARIANT_2003` (removed 8.0) |
| `CONST-FILTER-STRING` | Medium | `FILTER_SANITIZE_STRING` / `_STRIPPED` (deprecated 8.1) |
| `CONST-MT-RAND-PHP` | Low | `MT_RAND_PHP` (deprecated 8.3) |
| `CONST-E-STRICT` | Low | `E_STRICT` (deprecated 8.4) |
| `PDO-DRIVER-CONSTANTS` | Low | `PDO::MYSQL_ATTR_*`, `PDO::SQLITE_*`, ... (deprecated 8.5) |
| `INI-REMOVED` | High | `ini_set` / `ini_get` of removed directives: `register_globals`, `magic_quotes_*`, `safe_mode`, `track_errors`, `asp_tags`, `mbstring.func_overload`, ... |

### Legacy database and database security

The removed `mysql_*` / `mssql_*` / `sqlite_*` functions and the other old database extensions are reported as `FN-*` findings in the **Legacy Database** category, with specific mysqli/PDO replacements. On top of that:

| Rule | Severity | Detects |
|---|---|---|
| `DB-SQL-CONCAT` | High | `mysql(i)_query`, `pg_query`, `sqlsrv_query`, `->query()`, `->exec()` or `->prepare()` called with a query that interpolates or concatenates variables |
| `DB-SQL-BUILD` | Medium | `"SELECT ... FROM ... $id"`, `'UPDATE t SET ... ' . $x`, and similar SQL strings built from variables |
| `DB-ADDSLASHES` | Medium | `addslashes()` (not safe for SQL escaping) |
| `DB-MANUAL-ESCAPE` | Low | `mysqli_real_escape_string`, `->real_escape_string()`, `pg_escape_string`. Recommends prepared statements |

### Compatibility layers

| Rule | Severity | Detects |
|---|---|---|
| `COMPAT-SHIM-DEFINITION` | High | Userland definitions of removed functions, e.g. `function mysql_query(...)` or `function ereg(...)` (class methods are excluded) |
| `COMPAT-SHIM-GUARD` | Medium | `function_exists('mysql_connect')`, `function_exists('each')`, ... |
| `COMPAT-POLYFILL-GUARD` | Low | `function_exists('str_contains')`, `'random_bytes'`, `'array_key_first'`, ... (polyfills for functions that now exist natively) |
| `COMPAT-INCLUDE` | Medium | `require` / `include` of files named `*shim*`, `*compat*`, `*polyfill*`, `*legacy*`, `mysql2i`, ... |
| `COMPAT-MYSQL2I` | High | Use of the `mysql2i` emulation class |
| `COMPAT-VERSION-BRANCH` | Low | `version_compare(PHP_VERSION, '5.x' / '7.x')`, `PHP_VERSION_ID < 70000`, `PHP_MAJOR_VERSION == 5` |
| `COMPAT-REGISTER-GLOBALS` | High | `extract($_GET / $_POST / $_REQUEST ...)` |

### composer.json

Unless you pass `-NoComposerCheck`, every `composer.json` found is checked:

| Rule | Severity | Detects |
|---|---|---|
| `COMPOSER-PHP-CONSTRAINT` | Medium | `"php"` requirement that doesn't allow the target version, e.g. `^7.2` when the target is 8.5 |
| `COMPOSER-PLATFORM-PHP` | Medium | `config.platform.php` pinned below the target |
| `COMPOSER-COMPAT-PACKAGE` | High-Info | `dshafik/php7-mysql-shim`, `phpseclib/mcrypt_compat` (High). `paragonie/random_compat`, `ircmaxell/password-compat`, `symfony/polyfill-phpXY` at or below the target (Low). `symfony/polyfill-mbstring/iconv/ctype/intl-*`, `ralouphie/getallheaders` (Info) |

## .gitignore handling

By default the scan honours Git ignore rules, and ignored folders are never entered. Pass `-NoGitIgnore` to scan everything.

- Reads `.gitignore` in every folder (deeper files override higher ones) and `.git/info/exclude`.
- Supports comments, `!` negation, a leading `/` to anchor a pattern to its folder, a trailing `/` for folders only, `*`, `?`, `[abc]` / `[!abc]` and `**`. The last matching rule wins, as in Git.
- If you scan a subfolder of a repository, the script finds the repository root and also applies the `.gitignore` files above the scanned folder.
- Matching is case-insensitive, like Git on Windows (`core.ignorecase=true`).
- Git doesn't need to be installed. The matcher is built in and was verified to produce the same file list as `git ls-files --exclude-standard` on a test repository.
- `-ExcludeDirectory` still applies on top of the `.gitignore` rules.

## Suppressing findings

- **One line:** add a comment containing `phpscan:ignore` to the line.

  ```php
  $n = count($rows); // phpscan:ignore - $rows is always an array here
  ```

- **A whole file:** put `phpscan:ignore-file` anywhere in the file, usually in the header comment.
- **Folders:** use `-ExcludeDirectory` or `.gitignore`.
- **Noise level:** use `-MinSeverity Medium` (or higher), or untick severities in the HTML report.

## Testing

The Pester test suite is in `tests\`. It needs **Pester 5 or later**. Windows ships with Pester 3.4, which is too old. To install a current version for your account only:

```powershell
Install-Module Pester -MinimumVersion 5.0 -Scope CurrentUser -Force -SkipPublisherCheck
```

Run the tests from the repository root:

```powershell
Invoke-Pester .\tests                    # summary
Invoke-Pester .\tests -Output Detailed   # every test
```

The suite covers:

- **Script health:** it parses, it is ASCII-only (required for Windows PowerShell 5.1), it compiles no code (the only `Add-Type` allowed is `-AssemblyName`), and it runs under `powershell.exe` 5.1 when that is available.
- **Rules:** every rule is checked against `tests\fixtures\rules\` (`legacy.php`, `more-rules.php`, `lib\mysql_shim.php`, `composer.json`). Each test asserts the expected rule ID and severity on a specific line. Other tests assert there is *no* finding for comments, heredocs, inline HTML/JS, guarded calls, `->each()` / `Foo::split()`, `phpscan:ignore`, and modern PHP 8 code.
- **Options:** `-TargetVersion`, `-MinSeverity`, `-ExcludeDirectory`, `-Extensions`, `-MaxFileSizeMB`, `-NoComposerCheck`, `phpscan:ignore-file`, `-OutputPath` (file and directory), the CSV columns and HTML rows, the header-only CSV, and the `-FailOn` exit codes.
- **composer.json:** the PHP constraint evaluator (`^`, `~`, `.*`, ranges, `||`).
- **.gitignore:** a repository is generated in `TestDrive` at run time. Its file list is compared with `git ls-files --cached --others --exclude-standard` (skipped if Git isn't installed), and each of 22 files has its own included/excluded test. There are also tests for parent `.gitignore` files applying to subfolder scans, the HTML summary, `-NoGitIgnore`, the legacy `-UseGitIgnore`, and the warning when both are given.

The fixture tests refer to line numbers, so only **append** new lines to the fixture PHP files. The test repository is generated at run time so that its `.gitignore` files never affect this project's own Git repository.

## Limitations

**It is pattern matching, not a PHP parser.** The script strips comments, inline HTML and (for most rules) string contents, then applies regular expressions. This makes it fast and dependency-free, but:

- **False positives are expected** for the broad checks: `COUNT-VARIABLE`, `STRLEN-VARIABLE`, `SYN-NESTED-TERNARY`, `DB-SQL-BUILD`, `LIST-MODERNISE`. The script has no type information, so it can't know that `$rows` is always an array. These checks are deliberately rated Medium, Low or Info. Treat them as a review list, not as definite bugs.
- **False negatives are possible.** Things it can't see:
  - dynamic calls such as `$fn()`, `call_user_func('mysql_query', ...)` or `array_map('utf8_encode', ...)`
  - values whose type is only known at runtime, e.g. `count()` on a variable that is sometimes `null`, or `list()` from a string variable
  - dynamic properties (deprecated in 8.2), static calls to non-static methods, and changed function signatures or return types
  - multi-line function signatures, for the optional-before-required and implicitly nullable checks
- **Guards only count on the same line.** An `is_array($x)` check on the previous line doesn't suppress `count($x)`.
- **One finding per line per rule group.** If several `count()` calls share a line, only the most severe is reported.
- **Same-name methods are excluded.** Calls like `$obj->each()` or `Foo::split()` are deliberately skipped. A real global function called through an unusual namespace alias may be missed.
- **PHP 4 constructor detection** only covers classes in non-namespaced files that don't define `__construct`.
- **Files are read as UTF-8 (or by BOM).** Legacy-encoded files are still scanned correctly, because all the patterns are ASCII, but non-ASCII characters may look garbled in the report's `Code` column.
- **Files with no `<?` / `<%` / `<script` tag are skipped**, as they contain no PHP. Code inside `<script language="php">` blocks is flagged but not scanned further.
- **PHP 8.5 rules were written from memory of the 8.5 deprecation list.** Confirm these against the official PHP 8.5 migration guide before acting on them: the driver-specific PDO constants, `$http_response_header`, and the no-op `*_close` / `imagedestroy` calls. They are all rated Low. There are no rules for versions after 8.5.
- **.gitignore:** the global `core.excludesFile` is not read. Files that are committed but match an ignore pattern are skipped, whereas Git would still track them.
- **Large result sets:** on big legacy codebases the HTML report can reach tens of MB, for example about 27 MB for 49,000 findings, and become slow in the browser. Use the CSV, `-MinSeverity`, or scan subfolders separately. For reference, 1,000 heavily affected files scan in about 30 seconds in PowerShell 5.1.

The report shows what needs attention. It doesn't replace running your test suite on the target PHP version with `error_reporting(E_ALL)`, or a full static analyser such as PHPStan or Psalm, or PHPCompatibility for PHP_CodeSniffer.
