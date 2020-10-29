---
layout: default
title: Confirmation
nav_order: 9
has_children: true
---

Confirmation
===

The `Auth` class takes as confirmation service that can be use to create and verify confirmation tokens. This is useful
to require a user to confirm signup by e-mail or for a password reset functionality.

## No confirmation

By default the `Auth` service has a stub object that can't create confirmation tokens. Using `$auth->confirm()`, without
passing a confirmation when creating `Auth`, will throw an exception.

## Hashids

The `HashidsConfirmation` service creates tokens that includes the user id, expire date, and a checksum using the
[Hashids](https://hashids.org/php/) library.

    composer require hashids/hashids

### Setup

```php
use Jasny\Auth\Auth;
use Jasny\Auth\Authz;
use Jasny\Auth\Confirmation\HashidsConfirmation;

$secret = base64_decode(getenv('AUTH_CONFIRMATION_SECRET')); // Secret is a base64 encoded random 32 byte string
$confirmation = new HashidsConfirmation($secret);

$levels = new Authz\Levels(['user' => 1, 'admin' => 20]);
$auth = new Auth($levels, new AuthStorage(), $confirmation);
```

### Security

**The token doesn't depend on hashids for security**, since hashids is _not a true encryption algorithm_. While the user
id and expire date are obfuscated for a casual user, a hacker might be able to extract this information.

The token contains a SHA-256 checksum. This checksum includes a confirmation secret. To keep others from generating
tokens, the a strong secret must be used. Make sure the confirmation secret is sufficiently long, like 32 random
characters. A short secret might be guessed through brute forcing. Generating a strong secret can be done by running

    php -r 'echo base64_encode(random_bytes(32));'

It's recommended to configure the secret through an environment variable and not put it in your code.

### Custom encoding of uid

By default user IDs are treated as a (binary) string. Encoding them simply takes the byte values and convert it into a
hexidecimal value using `unpack('H*', $uid)`.

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

## Custom confirmation service

Hashids tokens contain all the relevant information and a checksum, which can make the quite long. An alternative is
generating a random value and storing it to the DB.

It's possible to create a custom confirmation service by implementing the `ConfirmationInterface`. The service should
be immutable.

```php
use Jasny\Auth\Confirmation\ConfirmationInterface;
use Jasny\Auth\Confirmation\InvalidTokenException;
use Jasny\Auth\StorageInterface;
use Jasny\Auth\UserInterface;

class MyCustomConfirmation implements ConfirmationInterface
{
    protected Storage $storage;
    protected string $subject;

    protected function storeToken(string $token, string $uid, string $authChecksum, \DateTimeInterface $expire): void
    {
        // Store token with user id, auth checksum, subject and expire date to DB
    }

    protected function fetchTokenInfo(string $token): ?array
    {
        // Query DB and return uid, expire date and subject for given token
    }


    public function withStorage(StorageInterface $storage)
    {
        $clone = clone $this;
        $clone->storage = $storage;

        return $clone;
    }

    public function withSubject(string $subject)
    {
        $clone = clone $this;
        $clone->subject = $subject;

        return $clone;
    }

    public function withLogger(\Psr\Log\LoggerInterface $logger)
    {
        // ...
    }

    public function getToken(UserInterface $user, \DateTimeInterface $expire): string
    {
        $token = base_convert(bin2hex(random_bytes(32)), 16, 36);
        $this->storeToken($token, $user->getAuthId(), $user->getAuthChecksum(), $expire);
    
        return $token;
    }

    public function from(string $token): UserInterface
    {
        $info = $this->fetchTokenInfo($token);
        
        if ($info === null) {
            throw new InvalidTokenException("Invalid token");
        }

        ['uid' => $uid, 'authChecksum' => $authChecksum, 'expire' => $expire, 'subject' => $subject] = $info;

        if ($expire < new \DateTime()) {
            throw new InvalidTokenException("Token expired");
        }

        if ($subject !== $this->subject) {
            throw new InvalidTokenException("Invalid token");
        }

        $user = $this->storage->fetchUserById($uid);

        if ($user === null || $user->getAuthChecksum() !== $authChecksum) {
            throw new InvalidTokenException("Invalid token");
        }

        return $user;
    }
}
```
