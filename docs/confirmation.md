Confirmation
---

The `Auth` class takes as confirmation service that can be use to create and verify confirmation tokens. This is useful
to require a user to confirm signup by e-mail or for a password reset functionality.

### No confirmation

By default the `Auth` service has a stub object that can't create confirmation tokens. Using `$auth->confirm()`, without
passing a confirmation when creating `Auth`, will throw an exception.

### Hashids

The `HashidsConfirmation` service creates tokens that includes the user id, expire date, and a checksum using the
[Hashids](https://hashids.org/php/) library.

    composer require hashids/hashids

#### Setup

```php
use Jasny\Auth\Auth;
use Jasny\Auth\Authz;
use Jasny\Auth\Confirmation\HashidsConfirmation;

$confirmation = new HashidsConfirmation(getenv('AUTH_CONFIRMATION_SECRET'));

$levels = new Authz\Levels(['user' => 1, 'admin' => 20]);
$auth = new Auth($levels, new AuthStorage(), $confirmation);
```

#### Security

**The token doesn't depend on hashids for security**, since hashids is _not a true encryption algorithm_. While the user
id and expire date are obfuscated for a casual user, a hacker might be able to extract this information.

The token contains a SHA-256 checksum. This checksum includes a confirmation secret. To keep others from generating
tokens, the a strong secret must be used. Make sure the confirmation secret is sufficiently long, like 32 random
characters. A short secret might be guessed through brute forcing.

It's recommended to configure the secret through an environment variable and not put it in your code.

### Examples

#### Signup confirmation

Get a verification token. Use it in an url and set that url in an e-mail to the user.

```php
$user = new User();
// Set the user info

$expire = new \DateTime('+30days');
$token = $auth->confirm('signup')->getToken($user, $expire);

$url = "https://{$_SERVER['HTTP_HOST']}/confirm.php?token=$token";
    
mail(
  $user->email,
  "Welcome to our site",
  "Please confirm your account by visiting $url"
);
```

Use the confirmation token to fetch and verify the user

```php
use Jasny\Auth\Confirmation\InvalidTokenException;

try {
    $user = $auth->confirm('signup')->from($_GET['token']);
} catch (InvalidTokenException $exception) {
    http_response_code(400);
    echo "The token is not valid";
    exit();
}

// Process the confirmation
// ...
```

#### Forgot password

Get a verification token. Use it in an url and set that url in an e-mail to the user.

```php
$user = ...; // Get the user from the DB by email

$expire = new \DateTime('+48hours');
$token = $auth->confirm('reset-password')->getToken($user, $expire);

$url = "https://{$_SERVER['HTTP_HOST']}/reset.php?token=$token";

mail(
  $user->email,
  "Password reset request",
  "You may reset your password by visiting $url"
);
```

Use the confirmation token to fetch and verify resetting the password

```php
use Jasny\Auth\Confirmation\InvalidTokenException;

try {
    $user = $auth->confirm('reset-password')->from($_GET['token']);
} catch (InvalidTokenException $exception) {
    http_response_code(400);
    echo "The token is not valid";
    exit();
}

$expire = new \DateTime('+1hour');
$postToken = $auth->confirm('change-password')->getToken($user, $expire);

// Show form to set a password
// ...
```

Use the new 'change-password' token to verify changing the password

```php
use Jasny\Auth\Confirmation\InvalidTokenException;

try {
    $user = $auth->confirm('change-password')->from($_POST['token']);
} catch (InvalidTokenException $exception) {
    http_response_code(400);
    echo "The token is not valid";
    exit();
}

$user->changePassword($_POST['password']);

// Save the user to the DB
```

### Custom confirmation service

Hashids tokens contain all the relevant information and a checksum, which can make the quite long. An alternative is
generating a random value and storing it to the DB.

It's possible to create a custom confirmation service by implementing the `ConfirmationInterface`. The service should
be immutable.

```php
use Jasny\Auth\Confirmation\ConfirmationInterface;
use Jasny\Auth\Confirmation\InvalidTokenException;
use Jasny\Auth\StorageInterface;
use Jasny\Auth\UserInterface;

class MyCustomConfirmation implements ConfirmationInterface
{
    protected Storage $storage;
    protected string $subject;

    protected function storeToken(string $token, string $uid, string $authChecksum, \DateTimeInterface $expire): void
    {
        // Store token with user id, auth checksum, subject and expire date to DB
    }

    protected function fetchTokenInfo(string $token): ?array
    {
        // Query DB and return uid, expire date and subject for given token
    }


    public function withStorage(StorageInterface $storage)
    {
        $clone = clone $this;
        $clone->storage = $storage;

        return $clone;
    }

    public function withSubject(string $subject)
    {
        $clone = clone $this;
        $clone->subject = $subject;

        return $clone;
    }

    public function withLogger(\Psr\Log\LoggerInterface $logger)
    {
        // ...
    }

    public function getToken(UserInterface $user, \DateTimeInterface $expire): string
    {
        $token = base_convert(bin2hex(random_bytes(32)), 16, 36);
        $this->storeToken($token, $user->getAuthId(), $user->getAuthChecksum(), $expire);
    
        return $token;
    }

    public function from(string $token): UserInterface
    {
        $info = $this->fetchTokenInfo($token);
        
        if ($info === null) {
            throw new InvalidTokenException("Invalid token");
        }

        ['uid' => $uid, 'authChecksum' => $authChecksum, 'expire' => $expire, 'subject' => $subject] = $info;

        if ($expire < new \DateTime()) {
            throw new InvalidTokenException("Token expired");
        }

        if ($subject !== $this->subject) {
            throw new InvalidTokenException("Invalid token");
        }

        $user = $this->storage->fetchUserById($uid);

        if ($user === null || $user->getAuthChecksum() !== $authChecksum) {
            throw new InvalidTokenException("Invalid token");
        }

        return $user;
    }
}
```

---

[Next chapter "Logging" >](logging.md)
