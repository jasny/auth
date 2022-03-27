<?php

declare(strict_types=1);

use Jasny\Auth\Auth;
use Jasny\Auth\LoginException;

(require __DIR__ . '/../vendor/autoload.php')
    ->setPsr4('', __DIR__ . '/includes');

/** @var Auth $auth */
$auth = require __DIR__ . '/includes/auth.php';

// Handle POST request
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        $auth->login((string)($_POST['username'] ?? ''), (string)($_POST['password'] ?? ''));
    } catch (LoginException $exception) {
        $error = $exception->getMessage();
    }
}

if ($auth->isLoggedIn()) {
    header('Location: index.php', true, 307);
    exit();
}

// Show the form in case of GET request
?>
<!doctype html>
<html>
    <head>
        <title>Login | Jasny Auth demo</title>

        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link rel="stylesheet" href="https://fonts.googleapis.com/css?family=Roboto:300,300italic,700,700italic">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/normalize/8.0.1/normalize.css">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/milligram/1.4.1/milligram.css">

        <style>
            .container {
                padding: 2rem;
            }
            
            .error {
                background: #fff3f3;
                border-left: 0.3rem solid #d00000;
                padding: 5px 5px 5px 10px;
                margin-bottom: 20px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Jasny Auth demo</small></h1>

            <?php if (isset($error)) : ?>
                <div class="error"><?= $error ?></div>
            <?php endif; ?>

            <form action="login.php" method="post">
                <label for="inputUsername">Username</label>
                <input type="text" name="username" id="inputUsername">

                <label for="inputPassword">Password</label>
                <input type="password" name="password" id="inputPassword">

                <button type="submit">Login</button>
            </form>
        </div>
    </body>
</html>
