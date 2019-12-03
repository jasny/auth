Jasny Auth
===

[![Build Status](https://travis-ci.org/jasny/auth.svg?branch=master)](https://travis-ci.org/jasny/auth)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/jasny/auth/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/jasny/auth/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/jasny/auth/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/jasny/auth/?branch=master)
[![Packagist Stable Version](https://img.shields.io/packagist/v/jasny/auth.svg)](https://packagist.org/packages/jasny/auth)
[![Packagist License](https://img.shields.io/packagist/l/jasny/auth.svg)](https://packagist.org/packages/jasny/auth)

Authentication, authorization and access control for PHP.

* [Installation](#installation)
* [Setup](#setup)
* [Usage](#usage)

---

Installation
---

Install using composer

    composer require jasny\auth

Usage
---

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


Setup
---

`Auth` is a composition class. It takes an [`Authz`](#authorization), [`Storage`](#storage), and optionally a
[`Confirmation`](#confirmation) service.

The `Auth` service isn't usable until it's initialized. This should be done after the session is started.

```php
session_start();
$auth->initialize();
```

### Storage

The `Storage` service is not provided, you'll need to create a service that can fetch a user from the database.

```php
use Jasny\Auth;

class AuthStorage implements Auth\StorageInterface
{
    /**
     * Fetch a user by ID
     */
    public function fetchUserById($id): ?Auth\UserInterface
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
    public function fetchContext($id) : ?Auth\ContextInterface
    {
        // Database action that fetches a context (or return null)
    }
}
```

### User

The fetch methods need to return a object that implements the `Jasny\Auth\UserInterface` interface.

```php
use Jasny\Auth;

class User implements Auth\UserInterface
{
    public int $id;
    public string $username;
    public int $accessLevel = 0;

    protected string $hashedPassword;

    /**
     * Get the user ID
     * 
     * @return int
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * Set the user's password.
     * {@interal This method isn't required by the interface}}. 
     */
    public function changePassword(string $password): void
    {
        $this->hashedPassword = password_hash($password, PASSWORD_BCRYPT);
    }

    /**
     * Verify that the password matches.
     */
    public function verifyPassword(string $password): bool
    {
        return password_verify($password, $this->hashedPassword);
    }

    /**
     * Get checksum/hash for critical user data like username, e-mail, and password.
     * If the checksum changes, the user is logged out in all sessions.
     */
    public function getAuthChecksum(): string
    {
        return hash('sha256', $this->username . $this->hashedPassword);
    }
    
    /**
     * Get the role of the user.
     * Uses authorization levels. 
     */
    public function getRole(Auth\ContextInterface $context = null): int
    {
        return $this->accessLevel;
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
use Jasny\Auth\Authz\Levels;

$levels = new Levels([
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
use Jasny\Auth\Authz\Groups;

$groups = new Groups([
    'users' => [],
    'managers' => [],
    'employees' => ['user'],
    'developers' => ['employees'],
    'paralegals' => ['employees'],
    'lawyers' => ['paralegals'],
    'lead-developers' => ['developers', 'managers'],
    'firm-partners' => ['lawyers', 'managers']
]);

$auth = new Auth($levels, new AuthStorage());
```

When using authorization groups the user may return multiple roles, which will be combined.

```php
use Jasny\Auth;

class User implements Auth\UserInterface
{
    public int $id;
    public string $username;
    public array $roles = [];

    protected string $hashedPassword;
    
    // ...

    public function getRole(?Auth\ContextInterface $context = null): array
    {
        return $this->roles;
    }
}
```

_It's always possible to switch from levels to groups, but usually not visa-versa._

### Context

By default authorization is global, aka application-wide. However it's possible to set an authz context like an
organization, team, or board. Rather than checking if a user is an admin in the application, you'd verify is the user
is an admin of the organization.

Any object that implements 'Jasny\Auth\ContextInterface' can be used as context. The `getAuthContextId()` method should
return a value that can be used by the [`Storage`](#storage) implementation to fetch the context.

```php
use Jasny\Auth;

class Organization implements Auth\ContextInterface
{
    public int $id;

    public function getAuthContextId()
    {
        return ['type' => 'organization', 'id' => $this->id];
    }
}
```

In some applications the context will be determined on a slug in the URL (like `ltonetwork` in
`https://github.com/ltonetwork/`). In that case `Context::getAuthContextId()` and `Storage::fetchContext()` should
return `null`.

You can either set the context for this request, or use an `Authz` object for that context with `inContextOf()`.

```php
if (!$auth->inContextOf($organization)->is('admin')) {
    return forbidden();
}

// OR

$auth->setContext($organization);

if (!$auth->is('admin')) {
    return forbidden();
}
```

### Events

__TODO__ 


Authentication
---

### login

    Auth::login(string $username, string $password): void

Login with username and password.

Triggers a [login event](#events), which may be used to cancel the login.

The method will throw a `LoginException` if login failed. The code will either be `LoginException::INVALID_CREDENTIALS`
or `LoginException::CANCELLED` (if cancelled via the login event).

### loginAs

    Auth::loginAs(UserInterface $user): void

Set user without verification. 

Triggers a [login event](#events), which may be used to cancel the login. The method will throw a `LoginException` if
the login is cancelled.

### setContext

    Auth::setContext(ContextInterface $context): void

Set the current authorization context for the user.

### logout

    Auth::logout(): void

Clear the current user and context.

Triggers a [logout event](#events).

### updateSession

    Auth::updateSession(): void
    
Store the current auth information in the session.

This typically doesn't have to be called explicitly. However, if the current user modifies his/her password (causing an
auth checksum mismatch), this needs to be called to prevent the current user from being logged out.

```php
$auth->user()->changePassword($_GET['new_password']);
$auth->updateSession();
```

### user

    Auth::user(): UserInterface|null
    
Get the current user. Returns `null` if no user is logged in.

### context

    Auth::context(): ContextInterface|null
    
Get the current context. Returns `null` if the global context is used.

### is

    Auth::is(string $role): bool

Check if a user has a specific role or superseding role

```php
if (!$auth->is('admin')) {
    http_response_code(403);
    echo "You're not allowed to see this page";
    exit();
}
```

### getAvailableRoles

    Auth::getAvailableRoles(): string[]

Get all defined authorization roles (levels or groups).


Access control (middleware)
---

Check if a user has a specific role or superseding role

    Jasny\Authz\Middleware asMiddleware(callback $getRequiredRole)

You can apply access control manually using the `is()` method. Alteratively, if you're using a PSR-7 compatible router
with middleware support (like [Jasny Router](https://github.com/jasny/router)]).

The `$getRequiredRole` callback should return a boolean, string or array of string.

Returning true means a the request will only be handled if a user is logged in.

```php
$auth = new Auth(); // Implements the Jasny\Authz interface

$router->add($auth->asMiddleware(function(ServerRequest $request) {
    return strpos($request->getUri()->getPath(), '/account/') === 0; // `/account/` is only available if logged in
}));
```

If the `Auth` class implements authorization (`Authz`) and the callback returns a string, the middleware will check if
the user is authorized for that role. If an array of string is returned, the user should be authorized for at least one
of the roles.

```php
$auth = new Auth(); // Implements the Jasny\Authz interface

$router->add($auth->asMiddleware(function(ServerRequest $request) {
    $route = $request->getAttribute('route');
    return isset($route->auth) ? $route->auth : null;
}));
```

Confirmation
---

The `Auth` class takes as confirmation service that can be use to create and verify confirmation tokens. This is useful
to require a user to confirm signup by e-mail or for a password reset functionality.

### No confirmation

By default the `Auth` service has a stub object that can't create confirmation tokens. Using `$auth->confirm()`, without
passing a confirmation when creating `Auth`, will throw an exception.

### Hashids

The `HashidsConfirmation` service creates tokens that includes the user id, expire date, and a checksum using the
[Hashids](https://hashids.org/php/) library.

A casual user will be unable to get the user id from the hash, but hashids is _not a true encryption algorithm_ and with
enough tokens a hacker might be able to determine the salt and extract the user id and checksum from tokens. _Note that
knowing the salt doesn't mean you know the configured secret._

The checksum is the first 24 bytes of the sha256 hash of user id, expire date. For better security you might add want to
use more than 12 characters. This does result in a larger string for the token.

You need to add a `getConfirmationSecret()` that returns a string that is unique and only known to your application.
Make sure the confirmation secret is suffiently long, like 20 random characters. For added security, it's better to
 configure it through an environment variable rather than putting it in your code.

```php
class Auth extends Jasny\Auth
{
  use Jasny\Auth\Confirmation;

  public function getConfirmationSecret()
  {
    return getenv('AUTH_CONFIRMATION_SECRET');
  }
}
```

#### Security


```php
class Auth extends Jasny\Auth
{
  ...

  protected function getConfirmationChecksum($id, $len = 32)
  {
    return parent::getConfirmationChecksum($id, $len);
  }

  ...
}
```

#### Signup confirmation

Get a verification token. Use it in an url and set that url in an e-mail to the user.

```php
$user = new User();

$expire = new \DateTime('+30days');
$token = $auth->confirm('signup')->getToken($user, $expire);

$url = "http://{$_SERVER['HTTP_HOST']}/confirm.php?token=$token";
    
mail(
  $user->email,
  "Welcome to our site",
  "Please confirm your account by visiting $url"
);
```

Use the confirmation token to fetch and verify the user

```php
use Jasny\Auth\Confirmation\InvalidTokenException;

try {
    $user = $auth->confirm('signup')->from($_GET['token']);
} catch (InvalidTokenException $exception) {
    http_response_code(400);
    echo "The token is not valid";
    exit();
}

// Process the confirmation
// ...
```

#### Forgot password

Get a verification token. Use it in an url and set that url in an e-mail to the user.

```php
$user = ...; // Get the user from the DB by email

$expire = new \DateTime('+48hours');
$token = $auth->confirm('reset-password')->getToken($user, $expire);

$url = "http://{$_SERVER['HTTP_HOST']}/reset.php?token=$token";

mail(
  $user->email,
  "Password reset request",
  "You may reset your password by visiting $url"
);
```

Use the confirmation token to fetch and verify resetting the password

```php
use Jasny\Auth\Confirmation\InvalidTokenException;

try {
    $user = $auth->confirm('reset-password')->from($_GET['token']);
} catch (InvalidTokenException $exception) {
    http_response_code(400);
    echo "The token is not valid";
    exit();
}

$expire = new \DateTime('+1hour');
$postToken = $auth->confirm('change-password')->getToken($user, $expire);

// Show form to set a password
// ...
```

Use the new 'change-password' token to verify changing the password

```php
use Jasny\Auth\Confirmation\InvalidTokenException;

try {
    $user = $auth->confirm('change-password')->from($_POST['token']);
} catch (InvalidTokenException $exception) {
    http_response_code(400);
    echo "The token is not valid";
    exit();
}

$user->changePassword($_POST['password']);

// Save the user to the DB
```
