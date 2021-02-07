---
layout: default
title: Forgot password
parent: Examples
grand_parent: Confirmation
nav_order: 2
---

Forgot password
===

Get a verification token. Use it in an url and set that url in an e-mail to the user.

```php
$user = ...; // Get the user from the DB by email

$expire = new \DateTime('+48hours');
$token = $auth->confirm('reset-password')->getToken($user, $expire);

$url = "https://{$_SERVER['HTTP_HOST']}/reset.php?token=$token";

mail(
  $user->email,
  "Password reset request",
  "You may reset your password by visiting $url"
);
```

Use the confirmation token to fetch and verify resetting the password

```php
use Jasny\Auth\Confirmation\InvalidTokenException;

try {
    $user = $auth->confirm('reset-password')->from($_GET['token']);
} catch (InvalidTokenException $exception) {
    http_response_code(400);
    echo "The token is not valid";
    exit();
}

$expire = new \DateTime('+1hour');
$postToken = $auth->confirm('change-password')->getToken($user, $expire);

// Show form to set a password
// ...
```

Use the new 'change-password' token to verify changing the password

```php
use Jasny\Auth\Confirmation\InvalidTokenException;

try {
    $user = $auth->confirm('change-password')->from($_POST['token']);
} catch (InvalidTokenException $exception) {
    http_response_code(400);
    echo "The token is not valid";
    exit();
}

$user->changePassword($_POST['password']);

// Save the user to the DB
```
