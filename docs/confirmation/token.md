---
layout: default
title: Random token
nav_order: 1
---

Random token
===

## TODO

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
