MFA (Multi-factor authentication)
---

This library support a two step verification process. The `User` object has a method `requiresMFA()`, which is called
during login. If this method returns `true`, the user will be partially logged in, requiring mfa verification to
complete to login.

Any MFA method can be used as long as it include verifying some sort of code or signature. Verification is delegated
to a callback that's configured using the `withMFA()` method. 

A good method is using time based one-time passwords according to [RFC 6238](http://tools.ietf.org/html/rfc6238) (TOTP),
compatible with Google Authenticator. This example uses the [OTPHP](https://github.com/Spomky-Labs/otphp) library.

```php
use Jasny\Auth\UserInterface;

class User implements UserInterface
{
    /** One time password secret for multi factor authentication (MFA) */
    public ?string $otpSecret = null;

    public requiresMFA(): bool
    {
        return $this->otpSecret !== null;
    }
}
```

```php
use OTPHP\TOTP;

$auth = (new Auth(...))
    ->withMfa(static function(User $user, string $code): bool {
        return TOPT::create($user->otpSecret)->verify($code);
    });
```

_If the MFA verification callback is not configured, MFA verification will always fail._

Other methods of verification might be an SMS OTP, [WebAuthn](https://webauthn.guide/), or email link.

#### Event

In case of partial login, a `PartialLogin` event is dispatched, rather than a `Login` event. The events are similar. The
`PartialLogin` event can be cancelled, which will trigger a `LoginException`.

#### Initializing OTP

Since Jasny Auth is agnostic towards the method of MFA, initializing OTP is outside of the scope of this library. Simply
follow the instructions of the library you're using. This is an example using OTPHP; 

```php
use OTPHP\TOTP;

$user->otpSecret = base_convert(bin2hex(random_bytes(8)), 16, 36); // 8 random bytes as alphanumeric string

$totp = TOTP::create($user->otpSecret); // New TOTP with custom secret
$totp->setLabel($user->email); // The label (string)

$totp->getProvisioningUri(); // Will return otpauth://totp/user@example.com?secret=ylsqrtotfc2r
``` 

### MFA verification

The `mfa` method will perform the second verification step and login the user fully if this is successful. 

```php
$auth->mfa($_POST['code']);
```

If the verification fails a `LoginException` will be thrown with code `LoginException::INVALID_CREDENTIALS`.

If the verification succeeds a `Login` event is dispatched, which may still be cancelled.

MFA verification may also be done for a fully logged in user.

#### Timeout

The partial login state will not automatically time out and live as long as the session live time. It's recommended to
check the authentication timestamp to limit the time between the first and second verification step.

```php
if ($auth->time() < new \DateTime("-5 minutes")) {
    header('Location: /login', true, 307);
    exit();
}

$auth->mfa($_POST['code']);
```

---

[Next chapter "Confirmation" >](confirmation.md)
