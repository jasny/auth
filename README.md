![jasny-banner](https://user-images.githubusercontent.com/100821/62123924-4c501c80-b2c9-11e9-9677-2ebc21d9b713.png)

Jasny Auth
===

[![PHP](https://github.com/jasny/auth/actions/workflows/php.yml/badge.svg)](https://github.com/jasny/auth/actions/workflows/php.yml)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/jasny/auth/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/jasny/auth/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/jasny/auth/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/jasny/auth/?branch=master)
[![Packagist Stable Version](https://img.shields.io/packagist/v/jasny/auth.svg)](https://packagist.org/packages/jasny/auth)
[![Packagist License](https://img.shields.io/packagist/l/jasny/auth.svg)](https://packagist.org/packages/jasny/auth)

Authentication, authorization and access control for [Slim Framework](https://www.slimframework.com/) and other PHP micro-frameworks.

**Features**

* Multiple [authorization strategies](https://www.jasny.net/auth/setup/roles), like groups (for acl) and levels.
* Authorization [context](https://www.jasny.net/auth/setup/context) (eg. "is the user an _admin_ of this _team_?").  
* PSR-14 [events](https://www.jasny.net/auth/authentication#events) for login and logout.
* PSR-15 [middleware](https://www.jasny.net/auth/middleware) for access control.
* [Session invalidation](https://www.jasny.net/auth/authentication#session-invalidation), explicit or implicit (eg.
    after password change).
* [Multi-factor authentication](https://www.jasny.net/auth/mfa/) support.
* [JWT](https://www.jasny.net/auth/sessions/jwt) and [Bearer authentication](https://www.jasny.net/auth/sessions/bearer)
    support.
* [Confirmation tokens](https://www.jasny.net/auth/confirmation/index) for sign up confirmation and forgot-password.
* PSR-3 [logging](https://www.jasny.net/auth/logging) of interesting events.
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

Documentation
---

* [Home](https://www.jasny.net/auth/)
* [Setup](https://www.jasny.net/auth/setup)
    * [Roles](https://www.jasny.net/auth/setup/roles)
    * [Storage](https://www.jasny.net/auth/setup/storage)
    * [User](https://www.jasny.net/auth/setup/user)
    * [Context](https://www.jasny.net/auth/setup/context)
* [Authentication](https://www.jasny.net/auth/authentication)
* [Authorization](https://www.jasny.net/auth/authorization)
* [Sessions](https://www.jasny.net/auth/sessions/)
    * [JWT](https://www.jasny.net/auth/sessions/jwt)
    * [Bearer](https://www.jasny.net/auth/sessions/bearer)
* [Middleware](https://www.jasny.net/auth/middleware.md) (for access control)
* [MFA](https://www.jasny.net/auth/mfa) (Multi-factor authentication)
    * [TOTP](https://www.jasny.net/auth/mfa/totp) _(aka Google authenticator)_
* [Confirmation](https://www.jasny.net/auth/confirmation)
    * [Random token](https://www.jasny.net/auth/confirmation/token)
    * [Hashids](https://www.jasny.net/auth/confirmation/hashids)
    * Examples
      * [Signup](https://www.jasny.net/auth/confirmation/examples/signup)
      * [Forgot password](https://www.jasny.net/auth/confirmation/examples/forgot_password)
* [Logging](https://www.jasny.net/auth/logging)
