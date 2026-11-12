<?php
if (!function_exists('mysql_query')) {
    function mysql_query($sql, $link = null) { return mysqli_query($link, $sql); }
}
if (!function_exists('str_contains')) {
    function str_contains($h, $n) { return strpos($h, $n) !== false; }
}
class Collection { public function each($cb) {} }
