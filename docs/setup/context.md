---
layout: default
title: Context
parent: Setup
nav_order: 4
---

Context
===

By default, authorization is global, aka application-wide. However, it's possible to set an authz context like a
**team**, organization, or board. Rather than checking if a user is an manager in the application, you'd verify is the
user is a manager of the team.

Any object that implements `Jasny\Auth\ContextInterface` can be used as context. The `getAuthId()` method should
return a value that can be used by the [`Storage`](storage.md) implementation to fetch the context.

```php
use Jasny\Auth;

class Team implements Auth\ContextInterface
{
    public string $id;

    public function getAuthId(): string
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
    
    public function getAuthRole(?Auth\ContextInterface $team = null): array
    {
        // Membership is an object that specifies the roles for the user within an team
        $membership = $team !== null
            ? $this->getMembership($team)
            : null;

        return array_merge($this->roles, $membership->roles ?? []);
    }
}
```

## Different type of contexts

In some cases an application has multiple types of authorization contexts. Take Trello for instance, it defines
application-wide, team, and board privileges.

```php
use Jasny\Auth;

class Team implements Auth\ContextInterface
{
    public string $id;

    public function getAuthId(): string
    {
        return "team:{$this->id}";
    }
}

class Board implements Auth\ContextInterface
{
    public string $id;

    public function getAuthId(): string
    {
        return "board:{$this->id}";
    }
}
```

It's up the storage class to determine which context to load

```php
use Jasny\Auth;

class AuthStorage implements Auth\StorageInterface
{
    // ...

    public function fetchContext(string $contextId): ?Auth\ContextInterface
    {
        [$type, $id] = explode(':', $contextId, 2);

        switch ($type) {
            case 'team':  return $this->fetchTeam($id);
            case 'board': return $this->fetchBoard($id);
            default:      throw new \Exception("Unknown context type '$type'");
        }
    }

    protected function fetchTeam(string $id): Team
    {
        // ...
    }

    protected function fetchBoard(string $id): Board
    {
        // ...
    }
}
```

## Default context for user

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

## Context from URL

In some applications the context will be determined on a slug in the URL (like `jasny` in `https://github.com/jasny/`).
In that case `Context::getAuthId()` should return `null` to prevent the context from being storing in the session.

```php
use Jasny\Auth;

class Team implements Auth\ContextInterface
{
    public function getAuthId(): ?string
    {
        return null;
    }
}
```

You need to manually set the context for each request.

```php
$teamSlug = get_slug_from_url($_SERVER['REQUEST_URI']);
$team = $auth->getStorage()->fetchContext($teamSlug);

$auth->setContext($team);

if (!$auth->is('manager')) {
    return forbidden();
}

$auth->context(); // returns $team
```

Alternatively, use a `Authz` object for with context for authorization instead of `Auth`. 

```php
if (!$auth->inContextOf($team)->is('manager')) {
    return forbidden();
}

$auth->context(); // returns null
```
