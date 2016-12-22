Auth
===

Authentication and level based authorization for PHP.


Installation
---

Install using composer

    composer require jasny\auth


Setup
---

`Jasny\Auth` is an abstract class. You need to extend it and implement the abstract methods `fetchUserById` and
`fetchUserByUsername`.

You also need to specify how the current user is persisted across requests. If you want to use normal PHP sessions, you
can simply use the `Auth\Sessions` trait.

```php
class Auth extends Jasny\Auth
{
    use Auth\Sessions;

    /**
     * Fetch a user by ID
     * 
     * @param int $id
     * @return User
     */
    public static function fetchUserById($id)
    {
        // Database action that fetches a User object
    }

    /**
     * Fetch a user by username
     * 
     * @param string $username
     * @return User
     */
    public static function fetchUserByUsername($username)
    {
        // Database action that fetches a User object
    }
}
```

The fetch methods need to return a object that implements the `Jasny\Auth\User` interface.

```php
class User implements Jasny\Auth\User
{
    /**
     * @var int
     */
    public $id;

    /**
     * @var string
     */
    public $username;

    /**
     * Hashed password
     * @var string
     */
    public $password;

    /**
     * @var boolean
     */
    public $active;


    /**
     * Get the user ID
     * 
     * @return int
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * Get the usermame
     * 
     * @return string
     */
    public function getUsername()
    {
        return $this->username;
    }

    /**
     * Get the hashed password
     * 
     * @return string
     */
    public function getHashedPassword()
    {
        return $this->password;
    }


    /**
     * Event called on login.
     * 
     * @return boolean  false cancels the login
     */
    public function onLogin()
    {
        if (!$this->active) {
            return false;
        }

        // You might want to log the login
    }

    /**
     * Event called on logout.
     */
    public function onLogout()
    {
        // You might want to log the logout
    }
}
```

### Authorization

By default the `Auth` class only does authentication. Authorization can be added by implementing the `Authz` interface.

Two traits are predefined to do Authorization: `Authz\ByLevel` and `Authz\ByGroup`.

#### By level

The `Authz\ByLevel` traits implements authorization based on access levels. Each user get permissions for it's level and
all levels below.

```php
class Auth extends Jasny\Auth implements Jasny\Authz
{
    use Jasny\Authz\ByLevel;

    /**
     * Authorization levels
     * @var array
     */
    protected $levels = [
        1 => 'user',
        10 => 'moderator',
        20 => 'admin',
        50 => 'superadmin'
    ];
}
```

For authorization the user object also needs to implement `Jasny\Authz\User`, adding the `getRole()` method. This method
must return the access level of the user, either as string or as integer.

    /**
     * Get the access level of the user
     * 
     * @return int
     */
    public function getRole()
    {
        return $this->access_level;
    }

#### By group

The `Auth\ByGroup` traits implements authorization using access groups. An access group may supersede other groups.

```php
class Auth extends Jasny\Auth implements Jasny\Authz
{
    use Jasny\Authz\ByGroup;

    /**
     * Authorization groups and each group is supersedes.
     * @var array
     */
    protected $groups = [
        'users' => [],
        'managers' => [],
        'employees' => ['user'],
        'developers' => ['employees'],
        'paralegals' => ['employees'],
        'lawyers' => ['paralegals'],
        'lead-developers' => ['developers', 'managers'],
        'firm-partners' => ['lawyers', 'managers']
    ];
}
```

For authorization the user object also needs to implement `Jasny\Authz\User`, adding the `getRole()` method. This method
must return the role of the user or array of roles.

    /**
     * Get the access groups of the user
     * 
     * @return string[]
     */
    public function getRoles()
    {
        return $this->roles;
    }


### Confirmation

By using the `Auth\Confirmation` trait, you can generate and verify confirmation tokens. This is useful to require a
use to confirm signup by e-mail or for a password reset functionality.

You need to add a `getConfirmationSecret()` that returns a string that is unique and only known to your application. For
security, it's best to configure it through an environment variable rather than putting it in your code.

class Auth extends Jasny\Auth
{
  use Jasny\Auth\Confirmation;

  public function getConfirmationSecret()
  {
    return getenv('AUTH_CONFIRMATION_SECRET');
  }
}


Usage
---

### Authentication

Verify username and password

    boolean verify(User $user, string $password)

Login with username and password

    User|null login(string $username, string $password);

Set user without verification

    User|null setUser(User $user)

_If `$user->onLogin()` returns `false`, the user isn't set and the function returns `null`._

Logout

    logout()

Get current user

    User user()


### Authorization

Check if a user has a specific role or superseding role

    boolean is(string $role)

```php
if (!$auth->is('admin')) {
    http_response_code(403);
    echo "You're not allowed to see this page";
    exit();
}
```

### Confirmation


#### Signup confirmation

Get a verification token. Use it in an url and set that url in an e-mail to the user.

```php
// Create a new $user

$auth = new Auth();
$confirmationToken = $auth->getConfirmationToken($user, 'signup');

$host = $_SERVER['HTTP_HOST'];
$url = "http://$host/confirm.php?token=$confirmationToken";
    
mail(
  $user->getEmail(),
  "Welcome to our site",
  "Please confirm your account by visiting $url"
);
```

Use the confirmation token to fetch and verify the user

```php
// --- confirm.php

$auth = new Auth();
$user = $auth->fetchUserForConfirmation($_GET['token'], 'signup');

if (!$user) {
    http_response_code(400);
    echo "The token is not valid";
    exit();
}

// Process the confirmation
// ...
```    

#### Forgot password

Get a verification token. Use it in an url and set that url in an e-mail to the user.

We use the hashed password in the token subject, so that the token will stop working once the password is changed.

```php
// Fetch $user by e-mail

$auth = new MyAuth();
$confirmationToken = $auth->getConfirmationToken($user, 'reset-password:' . $user->getHashedPassword());

$host = $_SERVER['HTTP_HOST'];
$url = "http://$host/reset.php?token=$confirmationToken";
    
mail(
  $user->getEmail(),
  "Welcome to our site",
  "Please confirm your account by visiting $url"
);
```

Use the confirmation token to fetch and verify resetting the password

```php
$auth = new MyAuth();
$user = $auth->fetchUserForConfirmation($_GET['token'], 'reset-password:' . $user->getHashedPassword());

if (!$user) {
    http_response_code(400);
    echo "The token is not valid";
    exit();
}

// Show form to set a password
// ...
```    
