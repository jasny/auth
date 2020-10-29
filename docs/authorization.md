---
layout: default
title: Authorization
nav_order: 5
---

Authorization
===

The `is()` method checks if the current user has the given role, or has a role that supersedes the given role. 

```php
if (!$auth->is('moderator')) {
    http_response_code(403);
    echo "You're not allowed to see this page";
    exit();
}

$auth->user()->getAuthRole(); // Returns 'admin' which supersedes 'moderator'.
```

## Methods

### isLoggedIn

    Auth::isLoggedIn(): bool
    
Check if the user is logged in.

### isPartiallyLoggedIn

    Auth::isPartiallyLoggedIn(): bool
    
Check if the user if partially logged in, in case of two-step verification (MFA).

### isLoggedOut

    Auth::isLoggedOut(): bool
    
Check if the user is not (partially) logged in.

### is

    Auth::is(string $role): bool

Check if the user has a specific role (or a role that supersedes it).

### getAvailableRoles

    Auth::getAvailableRoles(): string[]

Get all defined authorization roles (levels or groups).

### authz

    Auth::authz(): Authz

Returns a copy of the `Authz` service with the current user and context.

### forUser

    Auth::authz(User|null $user): Authz

Returns a copy of the `Authz` service with the given user, in the current context.

### inContextOf

    Auth::inContextOf(Context|null $context): Authz

Returns a copy of the `Authz` service with the current user, in the given context.

### outOfContext

    Auth::outOfContext(): Authz

Alias of `Auth::inContextOf(null)`.

## Immutability

The `Auth` service has a mutable state. This means that calling a method a second time with the same arguments can
give a different result, if the state has changed (by logging in or out, or changing the context).

```php
if (!$auth->is('admin')) {      // We only want to send the info to an admin.
    return forbidden();
}

doSomething();                  // If this function changed the current user,
sendInfoToAdmin($auth->user()); // the info could be send to a non-admin.
```

The `Authz` class is immutable and can also be used for authorization and access control.

```php
$authz = $auth->authz();

if (!$authz->is('admin')) {      // We only want to send the info to an admin.
    return forbidden();
}

doSomething();                   // If this function changed the current user,
sendInfoToAdmin($authz->user()); // the info will still be send to the admin.
```

## Authorize different user or context

`Authz` services have an immutable state. Calling `forUser()` and `inContextOf()` will return a modified copy of the
authorization service.

```php
$authz = $auth->authz();

$arnold = fetchUserByUsername('arnold');
$authzArnold = $authz->forUser($arnold);

// $authz and $authzArnold are *not* the same object
$authzArnold->is('admin');               // returns true
$authz->is('admin');                     // returns false, as no user is set

$jasny = fetchOrganizationByName("Jasny");
$authzArnoldAtJasny->inContextOf($jasny);
$authzArnoldAtJasny->is('owner');        // returns true;
```

`Auth::forUser()` and `Auth::inContextOf()` give a copy of the underlying authorization service. The following
statements are the equivalent

```php
$auth->forUser();
$auth->authz()->forUser();

$auth->inContextOf()
$auth->authz()->inContextOf()
```

Use `is()` to authorize the given user. The `user()` and `context()` methods are available to get the underlying user
and context.

```php
$authzArnoldAtJasny = $auth->forUser($arnold)->inContextOf($jasny);

// $auth isn't modified

$authzArnoldAtJasny->is('owner'); // return true
$authzArnoldAtJasny->user();      // returns the $arnold user
$authzArnoldAtJasny->context();   // returns the $jasny organization
```

## Authz recalc

The roles of the user are calculated and stored, so subsequent calls will always give the same result, even if the
underlying user object is modified.

```php
$authz->is('admin'); // returns true
$authz->user()->setRole('user');

$authz->is('admin'); // still returns true

$updatedAuthz = $authz->recalc();
$updatedAuthz->is('admin'); // returns false
```
