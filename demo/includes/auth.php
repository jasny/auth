<?php

declare(strict_types=1);

use Jasny\Auth\Auth;
use Jasny\Auth\Authz;

$levels = new Authz\Levels([
    'user' => 1,
    'admin' => 10,
]);

$auth = new Auth($levels, new AuthStorage());

session_start();
$auth->initialize();

return $auth;