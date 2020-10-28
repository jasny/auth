JSON Web Tokens
---

Jasny Auth supports JWT (JSON Web Tokens) as alternative method to store the user session. Using JWT requires the
[Lcobucci JWT v3](https://github.com/lcobucci/jwt) library.

    composer require lcobucci/jwt

Pass a `Jwt` object when initializing auth. It takes a builder and validation data.

```php
use Jasny\Auth\Session\Jwt;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\ValidationData;

$builder = (new Builder())
    ->issuedBy('http://example.com')      // Configures the issuer (iss claim)
    ->permittedFor('http://example.org'); // Configures the audience (aud claim)

$validation = new ValidationData();
$validation->setIssuer('http://example.com');
$validation->setAudience('http://example.com');

$jwt = new Jwt($builder, $validation);

$auth->initialize($jwt);
```

_For more information see [Lcobucci JWT documentation](https://github.com/lcobucci/jwt/blob/3.3/README.md)._

### Expire TTL

By default, the token will expire 24 hours after it has been issued. The `withTtl()` method allows changing this value.
The TTL (time to live) is specified in seconds.

```php
$jwt = (new Jwt($builder, $validation))
    ->withTtl(4 * 3600); // 4 hours
```

### Cookie

The JWT session handler sets and checks a cookie name `jwt` using `$_COOKIE` and `setcookie()`.

You can change the cookie parameters by passing a new `JWT\Cookie` object to `withCookie()`.

```php
use Jasny\Auth\Session\Jwt;

$jwt = (new Jwt($builder, $validation))
    ->withCookie(new Jwt\Cookie('my-web-token', ['domain' => 'example.com']));
```

The cookie expire time will always match the JWT expire time (exp claim) and can't be set.

### PSR-7

`AuthMiddleware` can be used to initialize a session from a PSR-7 server request. However, the auth middleware can only
get the cookie from the request, it's not able to set a cookie in the response.

Using `Jwt` with PSR-7 requires the use of `Jwt\CookieMiddleware`, which will create a `CookieValue` object which is
used instead of the global `$_COOKIE` and `setcookie()`. The cookie object is available as `jwt_cookie` attribute.

The cookie middleware will add a `Set-Cookie` header to the response if the cookie value has changed.

```php
use Jasny\Auth\AuthMiddleware;
use Jasny\Auth\Session\Jwt;
use Jasny\Auth\Session\Jwt\CookieMiddleware;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\ValidationData;
use Psr\Http\Message\ServerRequestInterface;

$router->add(new CookieMiddleware()); // Must be added before AuthMiddleware

$router->add((new AuthMiddleware(/* ... */))->withSession(
    function (ServerRequestInterface $request) {
        $builder = new Builder();
        $validation = new ValidationData();

        return (new Jwt($builder, $validation))
            ->withCookie($request->getAttribute('jwt_cookie'));
    });
);
```
