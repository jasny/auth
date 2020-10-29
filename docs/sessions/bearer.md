---
layout: default
title: Bearer authentication
parent: Sessions
nav_order: 2
---

Bearer authentication
===

The Auth service can be used for REST APIs that use bearer authentication rather than stateful sessions. The HTTP
request should contain header

    Authorization: Bearer <token> 

```php
use Jasny\Auth\Session\BearerAuth;

$auth->initialize(new BearerAuth());
```

For this type of authentication it's not possible to login or logout. Calling those methods will throw a
`LogicException`. It's also not possible to change the context. It should be automatically determined using
`AuthStorage::getContextForUser()`. Alternatively `inContextOf()` can be used.  

The `BearerAuth` constructor optionally takes a PSR-7 server request as first argument, and an id format as second
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
