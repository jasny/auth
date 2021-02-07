---
layout: default
title: Random token
nav_order: 1
---

Random token
===

The `TokenConfirmation` service creates a random confirmation token. This token must be stored to a database together
with the subject, user id and expiry date.

## Setup

```php
use Jasny\Auth\Auth;
use Jasny\Auth\Authz;
use Jasny\Auth\Confirmation\TokenConfirmation;

$confirmation = new TokenConfirmation();

$levels = new Authz\Levels(['user' => 1, 'admin' => 20]);
$auth = new Auth($levels, new AuthStorage(), $confirmation);
```

## Storage

To store the token, the storage class must implement `TokenStorageInterface`, adding two methods.

```php
use Jasny\Auth\StorageInterface;
use Jasny\Auth\Storage\TokenStorageInterface;
use Jasny\Auth\UserInterface;

class AuthStorage implements StorageInterface, TokenStorageInterface
{
    public \PDO $db;

    // ...
    
    /**
     * Save a confirmation token to the database.
     */
    public function saveToken(string $subject, string $token, UserInterface $user, \DateTimeInterface $expire): void
    {
        $this->db->prepare("INSERT INTO tokens (uid, subject, token, expire) VALUES (?, ?, ?, ?)")
            ->execute([$user->getAuthId(), $subject, $token, $expire->format('c')]);
    }

    /**
     * Fetch a user by a confirmation token.
     *
     * @phpstan-return array{uid:string,expire:\DateTimeInterface}|null
     */
    public function fetchToken(string $subject, string $token): ?array
    {
        $stmt = $this->db->prepare("SELECT uid, expire FROM tokens WHERE subject = ? AND token = ?");
        $stmt->execute([$subject, $token]);
        $info = $stmt->fetch(\PDO::FETCH_ASSOC);
        
        if ($info !== null) {
            $info['expire'] = new \DateTimeImmutable($info['expire']);
        }
        
        return $info;
    }
}
```