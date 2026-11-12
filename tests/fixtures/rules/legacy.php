<?php
// mysql_query("in a comment should be ignored");
/* ereg('x', $y); block comment */
$link = mysql_connect('localhost', 'u', 'p');
mysql_select_db('db', $link);
$id = $_GET['id'];
$res = mysql_query("SELECT * FROM users WHERE id = $id");
while ($row = mysql_fetch_assoc($res)) { echo $row['name']; }
$sql = 'SELECT * FROM t WHERE a = ' . $a;
$r = mysqli_query($conn, $sql);
if (ereg('^[0-9]+$', $id)) { $parts = split(',', $str); }
$f = create_function('$a', 'return $a * 2;');
while (list($k, $v) = each($arr)) { echo $k; }
list() = $x;
list($a[], $a[]) = [1, 2];
list($host, $port) = explode(':', $hostPort);
list($q, $w) = "ab";
[$z1, $z2] = $pair;
$c = count($items);
$c2 = is_array($items) ? count($items) : 0;
$c3 = count($_POST['ids']);
$c4 = count(json_decode($json));
$c5 = count("abc");
if (strlen($_GET['name']) > 0) {}
if (strlen($name) == 0) {}
$len = strlen($str);
$len2 = strlen($s ?? '');
$t = trim($_POST['title']);
$first = $str{0};
$f = (real) $x;
$y = &new Foo();
echo preg_replace('/(\w+)/e', 'strtoupper("\1")', $s);
parse_str($query);
define('FOO', 1, true);
echo implode($arr, ', ');
echo "Hello ${name}";
echo 'Not ${interp}';
$x = $a ? 1 : $b ? 2 : 3;
$ok = $a ? 1 : ($b ? 2 : 3);
function f(Foo $x = null, $y) {}
function g(?Foo $x = null) {}
$e = utf8_encode($s);
$d = strftime('%Y');
$s = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $k, $d, MCRYPT_MODE_CBC);
$h = $HTTP_POST_VARS['x'];
$m = MYSQL_ASSOC;
if (get_magic_quotes_gpc()) { $v = stripslashes($v); }
$coll->each(function() {});
Foo::split('x');
$safe = addslashes($v);
extract($_REQUEST);
if (version_compare(PHP_VERSION, '5.3.0', '<')) {}
if (!function_exists('mysql_connect')) { require_once 'lib/mysql_shim.php'; }
$x = (integer) $y;
trigger_error('x', E_USER_ERROR);
$heredoc = <<<SQL
SELECT * FROM t WHERE x = mysql_query($y) and ereg(
SQL;
$v = $x; // phpscan:ignore  mysql_query()
class String {}
class Widget {
    function Widget() { }
}
?>
<html><body><script>var n = count(items); mysql_query();</script>
<? echo $short; ?>
</body></html>
<!-- Tests reference line numbers in this file: only append new lines at the end. -->
