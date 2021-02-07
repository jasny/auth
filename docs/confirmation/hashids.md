---
layout: default
title: Hashids
parent: Confirmation
nav_order: 2
---

Hashids
===

The `HashidsConfirmation` service creates tokens that includes the user id, expire date, and a checksum using the
[Hashids](https://hashids.org/php/) library.

    composer require hashids/hashids

## Setup

```php
use Jasny\Auth\Auth;
use Jasny\Auth\Authz;
use Jasny\Auth\Confirmation\HashidsConfirmation;

$secret = base64_decode(getenv('AUTH_CONFIRMATION_SECRET')); // Secret is a base64 encoded random 32 byte string
$confirmation = new HashidsConfirmation($secret);

$levels = new Authz\Levels(['user' => 1, 'admin' => 20]);
$auth = new Auth($levels, new AuthStorage(), $confirmation);
```

## Security

**The token doesn't depend on hashids for security**, since hashids is _not a true encryption algorithm_. While the user
id and expire date are obfuscated for a casual user, a hacker might be able to extract this information.

The token contains a SHA-256 checksum. This checksum use HMAC with a confirmation secret. To keep others from generating
tokens, a strong secret must be used. Make sure the confirmation secret is sufficiently long, like 32 random characters.
A short secret might be guessed through brute forcing. Generating a strong secret can be done by running

    php -r 'echo base64_encode(random_bytes(32));'

It's recommended to configure the secret through an environment variable and not put it in your code.

## Custom encoding of uid

By default, user IDs are treated as a (binary) string. Encoding them simply takes the byte values and convert it into a
hexadecimal value using `unpack('H*', $uid)`.

However, if the uid has a specific format (eg an auto-incrementing integer or a UUID) it can be encoded more
efficiently, resulting in a shorter hashid token.

```php
use Ramsey\Uuid\Uuid;

$encodeUuid = function (string $uid) {
    return bin2hex(Uuid::fromString($uid)->getBytes());
}
$decodeUuid = function (string $hex) {
    return Uuid::fromBytes(hex2bin($hex))->toString();
}

$confirmation = (new HashidsConfirmation(getenv('AUTH_CONFIRMATION_SECRET')))
    ->withUidEncoded($encodeUuid, $decodeUuid);
```
