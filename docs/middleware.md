Access control (middleware)
---

You can apply access control manually using the `is()` method. Alteratively, if you're using a PSR-7 compatible router,
you can use middleware. `AuthMiddleware` implements [PSR-15 `MiddlewareInterface`](https://www.php-fig.org/psr/psr-15/).

Pass a [PSR-17 `ResponseFactory`](https://www.php-fig.org/psr/psr-17/#22-responsefactoryinterface) as last argument.
It's used to create a `401 Unauthorized` or `403 Forbidden` response. 

### Authorization

The constructor takes a callback as second argument, which should get the required authorization role / level from the
request.

The callback may return `null` to indicate that anybody can visit the page. Returning `true` means a the request will
only be handled if a user is logged in, and `false` means that the user may not be logged in.

```php
use Jasny\Auth\AuthMiddleware;
use Psr\Http\Message\ServerRequestInterface ;

$middleware = new AuthMiddleware(
    $auth,
    function (ServerRequestInterface $request) {
        if (strpos($request->getUri()->getPath(), '/account/') === 0) {
            return true; // Pages under `/account/` are only available if logged in
        }
        
        if ($request->getUri()->getPath() === '/signup') {
            return false; // Don't signup if you're already logged in
        }
    
        return null;
    },
    $responseFactory,
);

$router->add($middleware);
```

If the callback returns a string, the middleware will check if the user is authorized for that role.

```php
$middleware = new AuthMiddleware(
    $auth,
    function (ServerRequestInterface $request) {
        return $request->getAttribute('route.auth');
    },
    $responseFactory,
);

$router->add($middleware);
```

If an array of strings is returned, the user should be authorized for at least one of the roles. So returning 
`['admin', 'provider']` means the user needs to be an admin _OR_ provider.

### Initialization

The middleware will initialize the auth service. To use a different [session service](#sessions) than `PhpSessions`,
pass a callback to `withSession()`. The callback takes a PSR-7 `ServerRequestInterface` object and must return a
session service.

```php
$middleware = new AuthMiddleware(/* ... */)
    ->withSession(fn(ServerRequestInterface $request) => new BearerAuth($request));

$router->add($middleware);
```

A common case is to choose between bearer auth (for the API) and sessions based on the path.

```php
$middleware = new AuthMiddleware(/* ... */)
    ->withSession(function (ServerRequestInterface $request) {
        $isApi = strpos($request->getUri()->getPath(), '/api/') === 0);

        return $isApi
            ? new BearerAuth($request)
            : new SessionObject($request->getAttribute('session', new ArrayObject())); 
    });

$router->add($middleware);
```

### For multiple requests

Normally the Auth service should be initialized only once. Trying to initialize it a second time will throw an
exception. For testing (and in some rare other cases), you want to the service to be able to handle multiple request,
reading the session information each time. With `forMultipleRequests()` you get a copy of the service that allows
re-initialization.

```php
if (getenv('APPLICATION_ENV') === 'tests') {
    $auth = $auth->forMultipleRequests();
}
```

### Double pass middleware

Some HTTP dispatchers accept double pass middlware rather than adhering to PSR-15. This is supported via the
`asDoublePass()` method. In this case, the request factory may be omitted from the constructor.

```php
$middleware = new AuthMiddleware(/* ... */)
    ->withSession(function (ServerRequestInterface $request) {
        return new BearerAuth();
    });

$router->add($middleware->asDoublePass());
```

---

[Next chapter "Multi-factor authentication" >](mfa.md)
