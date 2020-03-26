Jasny Auth
===

Authentication, authorization and access control for PHP.

**Features**

* Multiple [authorization strategies](docs/setup.md#authorization-services), like groups (for acl) and levels.
* Authorization [context](docs/context.md) (eg. "is the user an _admin_ of this _team_").  
* PSR-14 [events](docs/authentication.md#events) for login and logout.
* PSR-15 [middleware](docs/middleware.md) for access control.
* [Session invalidation](docs/authentication.md#session-invalidation), explicit or implicit (eg. after password change).
* [Multi-factor authentication](docs/mfa.md) support.
* [Confirmation tokens](docs/confirmation.md) for sign up confirmation and forgot-password.
* PSR-3 [logging](docs/logging.md) of interesting events.
* Customizable to meet the requirements of your application.

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
$auth = new Auth($levels, new AuthStorage());

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
