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

    Auth::user(): UserInterface
    
Get the current user.

Use `isLoggedIn()` to see if there is a logged in user. This function throws an `AuthException` if no user is logged in.

#### time

    Auth::time(): \DateTimeInterface
    
Get the login timestamp.

### Events

Calling `login`, `loginAs` and `logout` will trigger an event. To capture these event, register a
[PSR-14](https://www.php-fig.org/psr/psr-14/) event dispatcher.

```php
use Jasny\Auth\Auth;
use Jasny\Auth\Authz;
use Jasny\Auth\Event;
use Jasny\EventDispatcher\EventDispatcher;
use Jasny\EventDispatcher\ListenerProvider;

$listeners = (new ListenerProvider())
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
    ->withEventDispatcher(new EventDispatcher($listeners));
```

#### Session fixation

In a [session fixation attack](https://en.wikipedia.org/wiki/Session_fixation), an attacker gets hold of user's session id
and keeps using it. In order to mitigate such an attack, the session id should be regenerated on login and the session
should be destroyed on logout.

```php
$listeners = (new ListenerProvider())
    ->withListener(function(Event\Login $login): void {
        session_regenerate_id();
    })
    ->withListener(function(Event\Logout $logout): void {
        session_destroy();
    });
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

### Session invalidation

The user's authentication checksum is stored in the session and verified on each request. On a mismatch, the user is
automatically logged out of the session.

Using the hashed password for the checksum means that user will be logged out of all sessions after a password change.
To keep him logged in in the current session call [`recalc()`](#recalc).

Alternatively, you can generate a random checksum. This would allow you to explicitly force the invalidation of other
sessions (for instance via the press of a button).

```php
use Jasny\Auth;

class User implements Auth\UserInterface
{
    public string $id;
    public string $username;
    public int $accessLevel = 0;

    protected string $hashedPassword;
    protected string $authChecksum;

    // ...
    
    public function forceLogout(): void
    {
        $this->authChecksum = bin2hex(random_bytes(32));
    }
   
    public function getAuthChecksum(): string
    {
        return $this->authChecksum;
    }
}
```

To log out for all sessions except the current:

```php
$auth->user()->forceLogout();
save_user_to_db($auth->user());

$auth->recalc();
```
---

[Next chapter "Context" >](context.md)
