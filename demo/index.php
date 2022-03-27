<?php

declare(strict_types=1);

use Jasny\Auth\Auth;

(require __DIR__ . '/../vendor/autoload.php')
    ->setPsr4('', __DIR__ . '/includes');

/** @var Auth $auth */
$auth = require __DIR__ . '/includes/auth.php';

if (!$auth->isLoggedIn()) {
    header('Location: login.php', true, 307);
    exit();
}

?>
<!doctype html>
<html>
    <head>
        <title>Jasny Auth demo</title>

        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Roboto:300,300italic,700,700italic">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/normalize/8.0.1/normalize.css">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/milligram/1.4.1/milligram.css">
        
        <style>
            .container {
                padding: 2rem;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Jasny Auth demo</h1>

            <h3>
                Logged in as <?= $auth->user()->username ?>
                <?php if ($auth->is('admin')): ?><small>(admin)</small><?php endif ?>
            </h3>

            <a id="logout" class="button" href="logout.php">Logout</a>
        </div>
    </body>
</html>
