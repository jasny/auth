<?php

declare(strict_types=1);

use Jasny\Auth\Auth;

(require __DIR__ . '/../vendor/autoload.php')
    ->setPsr4('', __DIR__ . '/includes');

/** @var Auth $auth */
$auth = require __DIR__ . '/includes/auth.php';

$auth->logout();

header('Location: index.php', true, 307);
exit();
