---
layout: default
title: Logging
nav_order: 10
---

Logging
---

You can supply a [PSR-3 compatible](https://www.php-fig.org/psr/psr-3/) logger to the `Auth` service.

```php
use Jasny\Auth\Auth;
use Jasny\Auth\Authz;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;

// create a log channel
$log = new Logger('auth');
$log->pushHandler(new StreamHandler('path/to/your.log'));

$levels = new Authz\Levels(['user' => 1, 'admin' => 20]);
$auth = (new Auth($levels, new AuthStorage()))
    ->withLogger($log);
```

The following events will be logged

* [info] Login successful
* [debug] Login failed: invalid credentials 
* [debug] Login failed: _{cancellation reason}_
* [info] Partial login
* [debug] MFA verification successful
* [debug] MFA verification failed
* [debug] Logout
* [notice] Ignoring auth info from session: invalid checksum

The auth id of the user is passed as logging context. For 'invalid credentials' the supplied username is passed as
context instead.

In case the user changes it's credentials (which results in a different auth checksum), other sessions are no longer
valid. In this case the user has any other sessions open (multiple browsers), 'invalid checksum' will be logged.

### Logging confirmation

The following event are logged when using Hashids confirmation tokens

* [info] Verified confirmation token
* [debug] Expired confirmation token
* [debug] Invalid confirmation token
* [debug] Invalid confirmation token: user not available
* [debug] Invalid confirmation token: bad checksum

The logging context will be the confirmation subject, the first 8 chars of the token, the user auth id, and the expire
date.
