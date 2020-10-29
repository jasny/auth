---
layout: default
title: TOTP
parent: MFA
nav_order: 1
---

TOTP MFA
===

A good method is using time based one-time passwords according to [RFC 6238](http://tools.ietf.org/html/rfc6238) (TOTP),
compatible with Google Authenticator.

This example uses the [OTPHP](https://github.com/Spomky-Labs/otphp) and other supporting libraries.

```
composer require spomky-labs/otphp
composer require paragonie/constant_time_encoding
composer require endroid/qr-code
```

## Set MFA verification callback

```php
use OTPHP\TOTP;

$auth = (new Auth(...))
    ->withMfa(static function(User $user, string $code): bool {
        return TOTP::create($user->otpSecret)->verify($code);
    });
```

_If the MFA verification callback is not configured, MFA verification will always fail._

## User class

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

## Enable TOTP for user

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

_It's good practise to verify the OTP code once to make sure the user has added it correctly to their app, before saving the otp secret to the DB. This requires temporarily storing the secret in a session. It isn't done in this example._
