---
layout: default
title: Setup
nav_order: 2
---

Setup
---

### Storage

The `Storage` service is not provided, you'll need to create a service that can fetch a user from the database.

```php
use Jasny\Auth;

class AuthStorage implements Auth\StorageInterface
{
    /**
     * Fetch a user by ID
     */
    public function fetchUserById(string $id): ?Auth\UserInterface
    {
        // Database action that fetches a User object
    }

    /**
     * Fetch a user by username
     */
    public function fetchUserByUsername(string $username): ?Auth\UserInterface
    {
        // Database action that fetches a User object
    }
    
    /**
     * Fetch the context by ID.
     */
    public function fetchContext(string $id) : ?Auth\ContextInterface
    {
        // Database action that fetches a context (or return null)
    }
    
    /**
     * Get the default context of the user.  
     */
    public function getContextForUser(Auth\UserInterface $user) : ?Auth\ContextInterface
    {
        return null;
    }
}
```

### User

The fetch methods need to return a object that implements the `Jasny\Auth\UserInterface` interface.

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

### Authorization services

The `Authz` services are used to check permissions for a user. These services are immutable, applying authorization to
the given user and context.

#### Levels

The `Authz\Levels` service implements authorization based on access levels. Each user get permissions for it's level and
all levels below. Levels must be integers.

```php
use Jasny\Auth\Auth;
use Jasny\Auth\Authz;

$levels = new Authz\Levels([
    1 => 'user',
    10 => 'moderator',
    20 => 'admin',
    50 => 'superadmin'
]);

$auth = new Auth($levels, new AuthStorage());
```

#### Groups

The `Authz\Groups` service implements authorization using access groups. An access group may supersede other groups.

```php
use Jasny\Auth\Auth;
use Jasny\Auth\Authz;

$groups = new Authz\Groups([
    'users' => [],
    'managers' => [],
    'employees' => ['user'],
    'developers' => ['employees'],
    'paralegals' => ['employees'],
    'lawyers' => ['paralegals'],
    'lead-developers' => ['developers', 'managers'],
    'firm-partners' => ['lawyers', 'managers']
]);

$auth = new Auth($groups, new AuthStorage());
```

When using authorization groups the user may return multiple roles, which will be combined.

```php
use Jasny\Auth;

class User implements Auth\UserInterface
{
    public string $id;
    public string $username;
    public array $roles = [];

    protected string $hashedPassword;
    
    // ...

    public function getAuthRole(?Auth\ContextInterface $context = null): array
    {
        return $this->roles;
    }
}
```

_It's always possible to switch from levels to groups, but usually not visa-versa._
