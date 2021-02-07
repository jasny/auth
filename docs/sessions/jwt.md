---
layout: default
title: JWT
parent: Sessions
nav_order: 1
---

JSON Web Tokens
===

Jasny Auth supports JWT (JSON Web Tokens) as alternative method to store the user session. Using JWT requires the
[Lcobucci JWT](https://github.com/lcobucci/jwt) library. Both v3 and v4 are supported.

    composer require lcobucci/jwt

Pass a `Jwt` object when initializing auth. It takes a `Lcobucci\JWT\Configuration` object.

```php
use Jasny\Auth\Session\Jwt;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Validation\Constraint;

$configuration = Configuration::forSymmetricSigner(
    new Sha256(),
    // replace the value below with a key of your own!
    InMemory::base64Encoded('mBC5v1sOKVvbdEitdSBenu59nfNfhwkedkJVNabosTw=')
);

$configuration->builder()
    ->issuedBy('http://example.com')                    // Configures the issuer (iss claim)
    ->permittedFor('http://example.org');               // Configure the audience (aud claim)

$configuration->setValidationConstraints(
    new Constraint\LooseValidAt(                        // Token should not be expired
        new SystemClock(new DateTimeZone('UTC')),
        new DateInterval('PT30S')
    ),
    new Constraint\IssuedBy('http://example.com'),      // Check the issuer
    new Constraint\PermittedFor('http://example.com'),  // Check the audience
);

$jwt = new Jwt($configuration);

$auth->initialize($jwt);
```

_For more information see [Lcobucci JWT documentation](https://lcobucci-jwt.readthedocs.io/en/latest/)._

## Expire TTL

By default, the token will expire 24 hours after it has been issued. The `withTtl()` method allows changing this value.
The TTL (time to live) is specified in seconds.

```php
$jwt = (new Jwt($configuration))
    ->withTtl(4 * 3600); // 4 hours
```

## Cookie

The JWT session handler sets and checks a cookie name `jwt` using `$_COOKIE` and `setcookie()`.

You can change the cookie parameters by passing a new `JWT\Cookie` object to `withCookie()`.

```php
use Jasny\Auth\Session\Jwt;

$jwt = (new Jwt($configuration))
    ->withCookie(new Jwt\Cookie('my-web-token', ['domain' => 'example.com']));
```

The cookie expire time will always match the JWT expire time (exp claim) and can't be set.

## PSR-7

`AuthMiddleware` can be used to initialize a session from a PSR-7 server request. However, the auth middleware can only
get the cookie from the request, it's not able to set a cookie in the response.

Using `Jwt` with PSR-7 requires the use of `Jwt\CookieMiddleware`, which will create a `CookieValue` object which is
used instead of the global `$_COOKIE` and `setcookie()`. The cookie object is available as `jwt_cookie` attribute.

The cookie middleware will add a `Set-Cookie` header to the response if the cookie value has changed.

```php
use Jasny\Auth\AuthMiddleware;
use Jasny\Auth\Session\Jwt;
use Jasny\Auth\Session\Jwt\CookieMiddleware;
use Lcobucci\JWT\Configuration;
use Psr\Http\Message\ServerRequestInterface;

$router->add(new CookieMiddleware()); // Must be added before AuthMiddleware

$router->add((new AuthMiddleware(/* ... */))->withSession(
    function (ServerRequestInterface $request) {
        $configuration = Configuration::forSymmetricSigner(/* ... */);

        return (new Jwt($configuration))
            ->withCookie($request->getAttribute('jwt_cookie'));
    });
);
```
