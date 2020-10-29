---
layout: default
title: Roles
parent: Setup
nav_order: 3
---

Roles
===

The `Authz` services are used to check permissions for a user. These services are immutable, applying authorization to
the given user and context.

## Levels

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

## Groups

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
