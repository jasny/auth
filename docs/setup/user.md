---
layout: default
title: User
parent: Setup
nav_order: 3
---

# User

The storage service must return an object that implements the `UserInterface` interface.

## Basic User

The `BasicUser` class only defines a few properties and methods. It should only be used for the `Auth` class in case the
rest of the application doesn't need a user object.

When the storage class has loaded data from the DB, it should call the static `BasicUser::fromData()` method to create a
user object.

## Custom class

If your application uses objects for the model, for instance through ORM, you should create a custom `User` class. This
class must implement `UserInterface`.

To support advanced features like MFA or triggered session invalidation, you also need to create a custom `User` class
and can't use `BasicUser`.

```php
use Jasny\Auth;

class User implements Auth\UserInterface
{
    public string $id;
    public string $username;
    public int $accessLevel = 0;

    protected string $hashedPassword = '';

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

If you're not using an ORM library like Doctrine, you should add a static `fromData()` method, which can turn data
loaded from the DB to a `User` object.
