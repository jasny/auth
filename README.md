Auth
===

[![Build Status](https://travis-ci.org/jasny/auth.svg?branch=master)](https://travis-ci.org/jasny/auth)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/jasny/auth/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/jasny/auth/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/jasny/auth/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/jasny/auth/?branch=master)
[![SensioLabsInsight](https://insight.sensiolabs.com/projects/2413e307-8b3b-4a7c-8202-730ed969bbd4/mini.png)](https://insight.sensiolabs.com/projects/2413e307-8b3b-4a7c-8202-730ed969bbd4)

Authentication and level based authorization for PHP.

* [Installation](#installation)
* [Setup](#setup)
* [Usage](#usage)


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

    protected function getAccessLevels()
    {
        return [
            1 => 'user',
            10 => 'moderator',
            20 => 'admin',
            50 => 'superadmin'
        ];
    }
}
```

If you get the levels from a database, make sure to save them in a property for performance.

```php
class Auth extends Jasny\Auth implements Jasny\Authz
{
    use Jasny\Authz\ByGroup;

    protected $levels;

    protected function getAccessLevels()
    {
        if (!isset($this->groups)) {
            $this->levels = [];
            $result = $this->db->query("SELECT name, level FROM access_levels");

            while (($row = $result->fetchAssoc())) {
                $this->levels[$row['name']] = (int)$row['level'];
            }
        }

        return $this->levels;
    }
}
```

For authorization the user object also needs to implement `Jasny\Authz\User`, adding the `getRole()` method. This method
must return the access level of the user, either as string or as integer.

```php
/**
 * Get the access level of the user
 * 
 * @return int
 */
public function getRole()
{
    return $this->access_level;
}
```

#### By group

The `Auth\ByGroup` traits implements authorization using access groups. An access group may supersede other groups.

You must implement the `getGroupStructure()` method which should return an array. The keys are the names of the
groups. The value should be an array with groups the group supersedes.

```php
class Auth extends Jasny\Auth implements Jasny\Authz
{
    use Jasny\Authz\ByGroup;

    protected function getGroupStructure()
    {
        return [
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
}
```

If you get the structure from a database, make sure to save them in a property for performance.

```php
class Auth extends Jasny\Auth implements Jasny\Authz
{
    use Jasny\Authz\ByGroup;

    protected $groups;

    protected function getGroupStructure()
    {
        if (!isset($this->groups)) {
            $this->groups = [];
            $result = $this->db->query("SELECT ...");

            while (($row = $result->fetchAssoc())) {
                $this->groups[$row['group']] = explode(';', $row['supersedes']);
            }
        }

        return $this->groups;
    }
}
```

For authorization the user object also needs to implement `Jasny\Authz\User`, adding the `getRole()` method. This method
must return the role of the user or array of roles.

```php
/**
 * Get the access groups of the user
 * 
 * @return string[]
 */
public function getRoles()
{
    return $this->roles;
}
```

### Confirmation

By using the `Auth\Confirmation` trait, you can generate and verify confirmation tokens. This is useful to require a
use to confirm signup by e-mail or for a password reset functionality.

You need to add a `getConfirmationSecret()` that returns a string that is unique and only known to your application.
Make sure the confirmation secret is suffiently long, like 20 random characters. For added security, it's better to
 configure it through an environment variable rather than putting it in your code.

```php
class Auth extends Jasny\Auth
{
  use Jasny\Auth\Confirmation;

  public function getConfirmationSecret()
  {
    return getenv('AUTH_CONFIRMATION_SECRET');
  }
}
```

#### Security

The confirmation token exists of the user id and a checksum, which is obfuscated using [hashids](http://hashids.org/).

A casual user will be unable to get the userid from the hash, but hashids is _not a true encryption algorithm_ and with
enough tokens a hacker might be able to determine the salt and extract the user id and checksum from tokens. _Note that
knowing the salt doesn't mean you know the configured secret._

The checksum is the first 16 bytes of the sha256 hash of user id + secret. For better security you might add want to
use more than 12 characters. This does result in a larger string for the token.

```php
class Auth extends Jasny\Auth
{   
  ...

  protected function getConfirmationChecksum($id, $len = 32)
  {
    return parent::getConfirmationChecksum($id, $len);
  }

  ...
}
```


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

Setting the 3th argument to `true` will use the hashed password of the user in the checksum. This means that the token
will stop working once the password is changed.

```php
// Fetch $user by e-mail

$auth = new MyAuth();
$confirmationToken = $auth->getConfirmationToken($user, 'reset-password', true);

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
$user = $auth->fetchUserForConfirmation($_GET['token'], 'reset-password', true);

if (!$user) {
    http_response_code(400);
    echo "The token is not valid";
    exit();
}

// Show form to set a password
// ...
```    
