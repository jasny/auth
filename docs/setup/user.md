---
layout: default
title: User
parent: Setup
nav_order: 2
---

# User

The storage service must return an object that implements the `Jasny\Auth\UserInterface` interface.

```php
use Jasny\Auth;

class User implements Auth\UserInterface
{
    public string $id;
    public string $username;
    public int $accessLevel = 0;

    protected string $hashedPassword;

    public function getAuthId(): string
    {
        return $this->id;
    }

    /**
     * {@interal This method isn't required by the interface}}. 
     */
    public function changePassword(string $password): void
    {
        $this->hashedPassword = password_hash($password, PASSWORD_BCRYPT);
    }

    public function verifyPassword(string $password): bool
    {
        return password_verify($password, $this->hashedPassword);
    }

    public function getAuthChecksum(): string
    {
        return hash('sha256', $this->id . $this->hashedPassword);
    }
    
    public function getAuthRole(Auth\ContextInterface $context = null): int
    {
        return $this->accessLevel;
    }

    public function requiresMfa() : bool
    {
        return false;
    }
}
```
