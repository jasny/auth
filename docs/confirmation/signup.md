---
layout: default
title: Signup
parent: Confirmation
nav_order: 1
---

## Signup confirmation

Get a verification token. Use it in an url and set that url in an e-mail to the user.

```php
$user = new User();
// Set the user info

$expire = new \DateTime('+30days');
$token = $auth->confirm('signup')->getToken($user, $expire);

$url = "https://{$_SERVER['HTTP_HOST']}/confirm.php?token=$token";
    
mail(
  $user->email,
  "Welcome to our site",
  "Please confirm your account by visiting $url"
);
```

Use the confirmation token to fetch and verify the user

```php
use Jasny\Auth\Confirmation\InvalidTokenException;

try {
    $user = $auth->confirm('signup')->from($_GET['token']);
} catch (InvalidTokenException $exception) {
    http_response_code(400);
    echo "The token is not valid";
    exit();
}

// Process the confirmation
// ...
```