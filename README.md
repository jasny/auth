Jasny Auth
===

[![Build Status](https://travis-ci.org/jasny/auth.svg?branch=master)](https://travis-ci.org/jasny/auth)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/jasny/auth/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/jasny/auth/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/jasny/auth/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/jasny/auth/?branch=master)
[![Packagist Stable Version](https://img.shields.io/packagist/v/jasny/auth.svg)](https://packagist.org/packages/jasny/auth)
[![Packagist License](https://img.shields.io/packagist/l/jasny/auth.svg)](https://packagist.org/packages/jasny/auth)

Authentication, authorization and access control for PHP.

**Features**

* Multiple [authorization strategies](#authorization-services), like groups (for acl) and levels.
* Authorization [context](#context) (eg. "is the user an _admin_ of this _team_").  
* PSR-14 [events](#events) for login and logout.
* PSR-15 [middleware](#access-control-middleware) for access control.
* [Confirmation tokens](#confirmation) for signup confirmation and forgot-password.
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

    public function getAuthId()
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
        return hash('sha256', $this->username . $this->hashedPassword);
    }
    
    public function getAuthRole(Auth\ContextInterface $context = null): int
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
    public int $id;
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

Authentication
---

`Auth` is a service with a mutable state. The login and logout methods change the current user.

### Methods

#### login

    Auth::login(string $username, string $password)

Login with username and password.

Triggers a [login event](#events), which may be used to cancel the login.

The method will throw a `LoginException` if login failed. The code will either be `LoginException::INVALID_CREDENTIALS`
or `LoginException::CANCELLED` (if cancelled via the login event).

#### loginAs

    Auth::loginAs(UserInterface $user)

Set user without verification. 

Triggers a [login event](#events), which may be used to cancel the login. The method will throw a `LoginException` if
the login is cancelled.

#### logout

    Auth::logout()

Clear the current user and context.

Triggers a [logout event](#events).

#### user

    Auth::user(): UserInterface|null
    
Get the current user. Returns `null` if no user is logged in.

### Events

Calling `login`, `loginAs` and `logout` will trigger an event. To capture these event, register a
[PSR-14](https://www.php-fig.org/psr/psr-14/) event dispatcher.

```php
use Jasny\Auth\Auth;
use Jasny\Auth\Authz;
use Jasny\Auth\Event;
use Jasny\EventDispatcher\EventDispatcher;
use Jasny\EventDispatcher\ListenerProvider;

$accessLog = ...; // Some access log service

$listener = (new ListenerProvider)
    ->withListener(function(Event\Login $login): void {
        if ($login->user()->isSuspended()) {
            $login->cancel("Sorry, you're account is suspended'");
        }
    })
    ->withListener(function(Event\Login $login): void {
        // do something
    })
    ->withListener(function(Event\Logout $logout): void {
        // do something
    });

$levels = new Authz\Levels(['user' => 1, 'moderator' => 10, 'admin' => 100]);

$auth = (new Auth($levels, new AuthStorage()))
    ->withEventDispatcher(new EventDispatcher($listener));
```

### Recalc

Recalculate the authz roles and store the current auth information in the session.

`Auth::recalc()` typically doesn't have to be called explicitly. If the current user modifies his/her password (causing an auth
checksum mismatch), this needs to be called to prevent the current user from being logged out.

```php
$auth->user()->changePassword($_GET['new_password']);
$auth->recalc();
```

If the role of the current user is changed, this also needs to be called to use the modified role for authorization.

```php
$auth->user()->setRole('admin');
$auth->is('admin'); // still returns false

$auth->recalc();
$auth->is('admin'); // returns true
```

Context
---

By default authorization is global, aka application-wide. However it's possible to set an authz context like an
organization, team, or board. Rather than checking if a user is an admin in the application, you'd verify is the user
is an admin of the organization.

Any object that implements 'Jasny\Auth\ContextInterface' can be used as context. The `getAuthId()` method should
return a value that can be used by the [`Storage`](#storage) implementation to fetch the context.

```php
use Jasny\Auth;

class Organization implements Auth\ContextInterface
{
    public int $id;

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
    public int $id;
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
    public int $id;

    public function getAuthId()
    {
        return "organization:{$this->id}";
    }
}
```

Authorization
---

The `is()` method checks if the current user has the given role, or has a role that supersedes the given role. 

```php
if (!$auth->is('moderator')) {
    http_response_code(403);
    echo "You're not allowed to see this page";
    exit();
}

$auth->user()->getAuthRole(); // Returns 'admin' which supersedes 'moderator'.
```

### Methods

#### is

    Auth::is(string $role): bool

Check if a user has a specific role or superseding role

#### getAvailableRoles

    Auth::getAvailableRoles(): string[]

Get all defined authorization roles (levels or groups).

#### authz

    Auth::authz(): Authz

Returns a copy of the `Authz` service with the current user and context.

#### forUser

    Auth::authz(User $user): Authz

Returns a copy of the `Authz` service with the given user, in the current context.

#### inContextOf

    Auth::inContextOf(Context $context): Authz

Returns a copy of the `Authz` service with the current user, in the given context.


### Immutable state

The `Auth` service has a mutable state. This means that calling a method a second time with the same arguments can
give a different result, if the state has changed (by logging in or out, or changing the context).

```php
if (!$auth->is('admin')) {      // We only want to send the info to an admin.
    return forbidden();
}

doSomething();                  // If this function changed the current user,
sendInfoToAdmin($auth->user()); // the info could be send to a non-admin.
```

Use `authz()` to prevent such issues.

```php
$authz = $auth->authz();

if (!$authz->is('admin')) {      // We only want to send the info to an admin.
    return forbidden();
}

doSomething();                   // If this function changed the current user,
sendInfoToAdmin($authz->user()); // the info will still be send to the admin.
```

#### Authorize other user

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

#### Recalc

The roles of the user are calculated and stored, so subsequent calls will always give the same result, even if the
underlying user object is modified.

```php
$authz->is('admin'); // returns true
$authz->user()->setRole('user');

$authz->is('admin'); // still returns true

$updatedAuthz = $authz->recalc();
$updatedAuthz->is('admin'); // returns false
```

Access control (middleware)
---

You can apply access control manually using the `is()` method. Alteratively, if you're using a PSR-7 compatible router,
you can use middleware. `AuthMiddleware` implements [PSR-15 `MiddlewareInterface`](https://www.php-fig.org/psr/psr-15/).

The constructor takes a callback, which should get the required authorization role / level from the request.

The callback may return `null` to indicate that anybody can visit the page. Returning `true` means a the request will
only be handled if a user is logged in, and `false` means that the user may not be logged in.

```php
use Jasny\Auth\AuthMiddleware;
use Psr\Http\Message\ServerRequestInterface ;

$middleware = new AuthMiddleware($auth, function (ServerRequestInterface $request) {
    if (strpos($request->getUri()->getPath(), '/account/') === 0) {
        return true; // Pages under `/account/` are only available if logged in
    }
    
    if ($request->getUri()->getPath() === '/signup') {
        return false; // Don't signup if you're already logged in
    }

    return null;
});

$router->add($middleware);
```

If the callback returns a string, the middleware will check if the user is authorized for that role.

```php
$auth = new Auth(); // Implements the Jasny\Authz interface

$router->add($auth->asMiddleware(function(ServerRequest $request) {
    return $request->getAttribute('route.auth');
}));
```

If an array of strings is returned, the user should be authorized for at least one of the roles. So returning 
`['admin', 'provider']` means the user needs to be an admin OR provider.

#### Initialization

`AuthMiddleware` will automatically initialize `Auth` if required.

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

    composer require hashids/hashids

#### Setup

```php
use Jasny\Auth\Auth;
use Jasny\Auth\Authz;
use Jasny\Auth\Confirmation\HashidsConfirmation;

$confirmation = new HashidsConfirmation(getenv('AUTH_CONFIRMATION_SECRET'));

$levels = new Authz\Levels(['user' => 1, 'admin' => 20]);
$auth = new Auth($levels, new AuthStorage(), $confirmation);
```

#### Security

**The token doesn't depend on hashids for security**, since hashids is _not a true encryption algorithm_. While the user
id and expire date are obfuscated for a casual user, a hacker might be able to extract this information.

The token contains a SHA-256 checksum. This checksum includes a confirmation secret. To keep others from generating
tokens, the a strong secret must be used. Make sure the confirmation secret is sufficiently long, like 32 random
characters. A short secret might be guessed through brute forcing.

It's recommended to configure the secret through an environment variable and not put it in your code.

### Examples

#### Signup confirmation

Get a verification token. Use it in an url and set that url in an e-mail to the user.

```php
$user = new User();
// Set the user info

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

### Custom confirmation service

Hashids tokens contain all the relevant information and a checksum, which can make the quite long. An alternative is
generating a random value and storing it to the DB.

It's possible to create a custom confirmation service by implementing the `ConfirmationInterface`. The service should
be immutable.

```php
use Jasny\Auth\Confirmation\ConfirmationInterface;
use Jasny\Auth\Confirmation\InvalidTokenException;
use Jasny\Auth\StorageInterface;
use Jasny\Auth\UserInterface;

class MyCustomConfirmation implements ConfirmationInterface
{
    protected Storage $storage;
    protected string $subject;

    protected function storeToken(string $token, string $uid, string $authChecksum, \DateTimeInterface $expire): void
    {
        // Store token with user id, auth checksum, subject and expire date to DB
    }

    protected function fetchTokenInfo(string $token): ?array
    {
        // Query DB and return uid, expire date and subject for given token
    }


    public function withStorage(StorageInterface $storage)
    {
        $clone = clone $this;
        $clone->storage = $storage;

        return $clone;
    }

    public function withSubject(string $subject)
    {
        $clone = clone $this;
        $clone->subject = $subject;

        return $clone;
    }

    public function getToken(UserInterface $user, \DateTimeInterface $expire): string
    {
        $token = base_convert(bin2hex(random_bytes(32)), 16, 36);
        $this->storeToken($token, $user->getAuthId(), $user->getAuthChecksum(), $expire);
    
        return $token;
    }

    public function from(string $token): UserInterface
    {
        $info = $this->fetchTokenInfo($token);
        
        if ($info === null) {
            throw new InvalidTokenException("Invalid token");
        }

        ['uid' => $uid, 'authChecksum' => $authChecksum, 'expire' => $expire, 'subject' => $subject] = $info;

        if ($expire < new \DateTime()) {
            throw new InvalidTokenException("Token expired");
        }

        if ($subject !== $this->subject) {
            throw new InvalidTokenException("Invalid token");
        }

        $user = $this->storage->fetchUserById($uid);

        if ($user === null || $user->getAuthChecksum() !== $authChecksum) {
            throw new InvalidTokenException("Invalid token");
        }

        return $user;
    }
}
```
