MFA (Multi-factor authentication)
---

This library support a two step verification process. The `User` object has a method `requiresMfa()`, which is called
during login. If this method returns `true`, the user will be partially logged in, requiring mfa verification to
complete to login.

Any MFA method can be used as long as it include verifying some sort of code or signature. Verification is delegated
to a callback that's configured using the `withMfa()` method. 

A good method is using time based one-time passwords according to [RFC 6238](http://tools.ietf.org/html/rfc6238) (TOTP),
compatible with Google Authenticator.

Other methods of verification might be an SMS OTP, [WebAuthn](https://webauthn.guide/), or an email link.

Since Jasny Auth is agnostic towards the method of MFA, initializing OTP is outside of the scope of this library. Simply
follow the instructions of the library you're using.

### TOTP example

This example uses the [OTPHP](https://github.com/Spomky-Labs/otphp) and other supporting libraries.

```
composer require spomky-labs/otphp
composer require paragonie/constant_time_encoding
composer require endroid/qr-code
```

#### Set MFA verification callback

```php
use OTPHP\TOTP;

$auth = (new Auth(...))
    ->withMfa(static function(User $user, string $code): bool {
        return TOTP::create($user->otpSecret)->verify($code);
    });
```

_If the MFA verification callback is not configured, MFA verification will always fail._

#### User class

```php
use Jasny\Auth\UserInterface;

class User implements UserInterface
{
    /** One time password secret for multi factor authentication (MFA) */
    public ?string $otpSecret = null;

    public requiresMfa(): bool
    {
        return $this->otpSecret !== null;
    }
}
```

#### Enable TOTP for user

```php
use Endroid\QrCode\QrCode;
use OTPHP\TOTP;
use ParagonIE\ConstantTime\Base32;

$user = $auth->user(); // Get current user from auth service

$user->otpSecret = Base32::encode(random_bytes(16)); // Secret must be base32 encoded
$user->save(); // Save user to DB

$totp = TOTP::create($user->otpSecret); // New TOTP with custom secret
$totp->setLabel($user->email); // The label (string)

$uri = $totp->getProvisioningUri(); // Will return "otpauth://totp/user@example.com?secret=JBSWY3DPEHPK3PXP"

$qrCode = new QrCode($uri); // Create QR code for URI

header('Content-Type: '.$qrCode->getContentType());
echo $qrCode->writeString();
``` 

### Checking partial login

If the user has logged in with username and password and requires MFA verification, it will be partially
logged in. This can be checked with `isPartiallyLoggedIn()`.

Partially logged in users should be redirected to the MFA form.

```php
$auth->login($_POST['username'], $_POST['password']);

if ($auth->isPartiallyLoggedIn()) {
    header('Location: /login/mfa', 303);
    echo "You're being redirected to <a href=\"/login/mfa\">MFA verfication</a>";
    exit();
}

// ...
```

The `isLoggedIn()` method returns `false`. The `is()` method will always return `false` for a partially
logged in users (regardless of the roles of the user).

### MFA verification

The `mfa` method will perform the second verification step and login the user fully if this is successful. 

```php
$auth->mfa($_POST['code']);
```

If the verification fails, a `LoginException` will be thrown with code `LoginException::INVALID_CREDENTIALS`.
The user will stay (partially) logged in, even if MFA verification fails. You may want to logout manually.

If the verification succeeds, a `Login` event is dispatched, which may still be cancelled. If cancelled, the user is
logged out.

MFA verification may also be done for a fully logged in user.

#### Timeout

The partial login state will not automatically time out and live as long as the session live time. It's recommended to
check the authentication timestamp to limit the time between the first and second verification step.

```php
if ($auth->time() < new \DateTime("-5 minutes")) {
    header('Location: /login', true, 303);
    exit();
}

$auth->mfa($_POST['code']);
```

### Event

In case of partial login, a `PartialLogin` event is dispatched, rather than a `Login` event. The events are similar. The
`PartialLogin` event can be cancelled, which will trigger a `LoginException`.

---

[Next chapter "Confirmation" >](confirmation.md)
