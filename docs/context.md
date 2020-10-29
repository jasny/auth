---
layout: default
title: Context
nav_order: 4
---

Context
---

By default, authorization is global, aka application-wide. However, it's possible to set an authz context like an
organization, team, or board. Rather than checking if a user is an admin in the application, you'd verify is the user
is an admin of the organization.

Any object that implements 'Jasny\Auth\ContextInterface' can be used as context. The `getAuthId()` method should
return a value that can be used by the [`Storage`](#storage) implementation to fetch the context.

```php
use Jasny\Auth;

class Organization implements Auth\ContextInterface
{
    public string $id;

    public function getAuthId()
    {
        return $this->id;
    }
}
```

```php
use Jasny\Auth;

class User implements Auth\UserInterface
{
    public string $id;
    public string $username;
    public array $roles = [];
    public array $memberships;

    protected string $hashedPassword;

    // ...
    
    public function getAuthRole(Auth\ContextInterface $context = null): array
    {
        $membership = $context !== null ? $this->getMembership($context) : null;

        return array_merge($this->roles, $membership->roles ?? []);
    }
}
```

### Methods

#### setContext

    Auth::setContext(ContextInterface $context)

Set the current authorization context for the user.

#### context

    Auth::context(): ContextInterface|null
    
Get the current context. Returns `null` if the global context is used.

### setContext vs inContextOf

In some applications the context will be determined on a slug in the URL (like `ltonetwork` in
`https://github.com/ltonetwork/`). In that case `Context::getAuthId()` and `Storage::fetchContext()` should
return `null`.

You can either set the context for this request

```php
if (!$auth->inContextOf($organization)->is('admin')) {
    return forbidden();
}

$auth->context(); // returns null
```

, or use an `Authz` object for that context with `inContextOf()`.

```php
$auth->setContext($organization);

if (!$auth->is('admin')) {
    return forbidden();
}

$auth->context(); // returns $organization
```

### Different type of contexts

In some cases an application has multiple types of authorization contexts. Take Trello for instance, it defines
application-wide, organization and board privileges.

In case the context is derived from the URL, both the `Organization` and `Board` class can return `null` for
`getAuthId()`. If the context needs to be stored in the session, prepend the id with the type;

```php
use Jasny\Auth;

class Organization implements Auth\ContextInterface
{
    public string $id;

    public function getAuthId()
    {
        return "organization:{$this->id}";
    }
}
```

### Default context for user

It might be possible to automatically determine the context for a user. For instance; the user might only be a member of
one team. The storage service must implement the method `getContextForUser()`. This method should return the default
context of the user.

```php
use Jasny\Auth;

class AuthStorage implements Auth\StorageInterface
{
    // ...

    public function getContextForUser(Auth\UserInterface $user): ?Auth\ContextInterface
    {
        return $user instanceof User && count($user->teams) === 1
            ? $user->teams[0]
            : null;
    }
}
```  
