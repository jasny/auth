Sessions
---

By default, the super global `$_SESSION` is used. Authentication info is stored under `$_SESSION['auth']`. To change the
way the information is stored, pass a session service when initializing.

```php
use Jasny\Auth\Session\PhpSession;

session_start();
$auth->initialize(new PhpSession('userinfo'));
```

### Session object

Use an object with `ArrayAccess` (like an `ArrayObject`) to store auth session information. Some libraries, like
[Jasny Session Middleware](https://github.com/jasny/session-middleware), support abstracting sessions via an object.
This makes it easier to test stateful applications.

```php
use Jasny\Auth\Session\SessionObject;

$session = new ArrayObject(['auth' => ['uid' => '123']]); // Session with test data
$auth->initialize(new SessionObject($session));
``` 

For testing it's possible to set `UserInterface` and `ContextInterface` objects as session information instead of
ids.


```php
use Jasny\Auth\Session\SessionObject;

$loggedInUser = new User('123', 'Arnold');
$currentContext = new Team('xyz');

$session = new ArrayObject(['auth' => ['uid' => $loggedInUser, 'context' => $currentContext]]);
$auth->initialize(new SessionObject($session));
``` 

### Bearer authentication

The Auth service can also be used for REST APIs that use bearer authentication rather than stateful sessions. The HTTP
request should contain header

    Authorization: Bearer <token> 

```php
use Jasny\Auth\Session\BearerAuth;

$auth->initialize(new BearerAuth());
```

For this type of authentication it's not possible to login or logout. Calling those methods will throw a
`LogicException`. It's also not possible to change the context. It should be automatically determined using
`AuthStorage::getContextForUser()`. Alternatively `inContextOf()` can be used.  

The `BearerAuth` constructor optionally takes a PSR-7 server request as first argument and an id format as second
argument. The format is used in `sprintf` to create the id from the token.

```php
class ApiKey implements Auth\UserInterface
{
    public function getAuthId()
    {
        return "key:{$this->token}";
    }
}

new BearerAuth($serverRequest, "apikey:%s");
```

---

[Next chapter "Access control" >](middleware.md)
