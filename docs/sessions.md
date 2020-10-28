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
