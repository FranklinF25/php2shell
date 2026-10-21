<?php
// php2shell lab probe — the application is irrelevant by design: PHP2Shell
// triggers during request startup, before any of this code runs. This script
// only proves the worker is alive and exposes its PID (same-worker oracle).
header('X-Worker-PID: ' . getmypid());
header('X-PHP-Version: ' . PHP_VERSION);
header('X-SAPI: ' . php_sapi_name());
echo 'php2shell-lab ok ', PHP_VERSION, ' ', php_sapi_name(), "\n";
