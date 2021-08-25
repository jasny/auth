---
layout: default
title: Home
nav_order: 1
description: "Authentication, authorization and access control for PHP"
permalink: /
---

Authentication, authorization and access control for PHP
{: .fs-6 .fw-300 }

**Features**

* Multiple [authorization strategies](setup/roles), like groups (for acl) and levels.
* Authorization [context](setup/context) (eg. "is the user an _admin_ of this _team_").  
* PSR-14 [events](authentication#events) for login and logout.
* PSR-15 [middleware](middleware) for access control.
* [Session invalidation](authentication#session-invalidation), explicit or implicit (eg.
    after password change).
* [Multi-factor authentication](mfa) support.
* [JWT](/sessions/jwt) and [Bearer authentication](sessions/bearer)
    support.
* [Confirmation tokens](confirmation) for sign up confirmation and forgot-password.
* PSR-3 [logging](logging) of interesting events.
* Customizable to meet the requirements of your application.

---

Installation
---

Install using composer

    composer require jasny/auth

Usage
---

`Auth` is a composition class. It takes an _authz_, _storage_, and optionally a _confirmation_ service.

```php
use Jasny\Auth\Auth;
use Jasny\Auth\Authz\Levels;

$levels = new Levels(['user' => 1, 'moderator' => 10, 'admin' => 100]);
$storage = new AuthStorage(); // See `setup` docs for this class
$auth = new Auth($levels, $storage);

session_start();
$auth->initialize();

// Later...
if (!$auth->is('admin')) {
    http_response_code(403);
    echo "Access denied";
    exit();
}
```

The `Auth` service isn't usable until it's initialized. This should be done after the session is started.

```php
session_start();
$auth->initialize();
```

### Context

It’s possible authorize in [context](setup/context) of a **team** or **organization**. Rather than checking if a user is an manager in the application, you’d verify is the user is a manager of the team.

```php
$team = fetchTeam($teamId);

if (!$auth->inContextOf($team)->is('manager')) {
    http_response_code(403);
    echo "Access denied";
    exit();
}
```
