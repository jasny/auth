---
layout: default
title: Confirmation
nav_order: 9
has_children: true
---

Confirmation
===

The `Auth` class takes as confirmation service that can be used to create and verify confirmation tokens. This is useful
to require a user to confirm signup by e-mail or for a password reset functionality.

To use a confirmation token, call the `confirm()` method, passing the subject. The subject prevents the token from being
used for a different purpose. For instance; it should not be possible to use a signup token to change the password.

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

[more examples &raquo;](token.md)

## No confirmation

By default, the `Auth` service has a stub object that can't create confirmation tokens. Using `$auth->confirm()`,
without passing a confirmation when creating `Auth`, will throw an exception.

## Random token

The `TokenConfirmation` service generates a random token. The token needs to be stored in the database in
such a way that the user information can be fetched for a URL that has the token as query parameter.

[learn more &raquo;](token.md)

## Hashids

The `HashidsConfirmation` service creates tokens that includes the user id, expire date, and a checksum
using the [Hashids](https://hashids.org/php/) library.

[learn more &raquo;](token.md)

## Custom confirmation service

It's possible to create a custom confirmation service by implementing the `ConfirmationInterface`. The service should
be immutable.
