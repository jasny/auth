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
`fetchUserByUsername`. Also set the `$secret` property to a [randomly selected](https://www.random.org/passwords/)
string.

By default 2 authentication levels are defined, normal users (user) and admin users (admin). You can change/add levels
by overwriting the `$level` property.

```php
class Auth extends Jasny\Auth
{
    /**
     * Authorization levels
     * @var array
     */
    protected static $levels = [
        1 => 'user',
        10 => 'moderator',
        20 => 'admin',
        50 => 'superadmin'
    ];

    /**
     * Secret word for creating a verification hash
     * @var string
     */
    protected static $secret = "A random string";
    

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
    public function getPassword()
    {
        return $this->password;
    }

    /**
     * Get the user's security level
     * 
     * @return int
     */
    public function getSecurityLevel()
    {
        return $this->security_level;
    }

    /**
     * Event called on login.
     * 
     * @return boolean  false cancels the login
     */
    public function onLogin()
    {
        if (!$this->active) return false;

        $this->last_login = new DateTime();
        $this->save();
        
        return true;
    }
}
```

Usage
---

### Basic methods

Login with username and password

    Auth::login($username, $password);

Logout

    Auth::logout();

Get logged in user

    Auth::user();

Check if user is allowed to do something

    if (!Auth::forLevel('admin')) die("Not allowed");


### Signup confirmation

Get a verification hash. Use it in an url and set that url in an e-mail to the user

```php
// Create a new $user
    
$confirmHash = generateConfirmationHash($user);
$url = 'http://' . $_SERVER['HTTP_HOST'] . '/confirm.php?hash=' . $hash;
    
// send email with $url to $user
```

Use the confirmation hash to fetch and verify the user

```php
// --- confirm.php

$user = Auth::fetchForConfirmation($_GET['hash']);
```    

### Forgot password

Forgot password works the same as the signup confirmation.

```php
// Fetch $user by e-mail
    
$confirmHash = generatePasswordResetHash($user);
$url = 'http://' . $_SERVER['HTTP_HOST'] . '/reset.php?hash=' . $hash;
    
// send email with $url to $user
```

Use the confirmation hash to fetch and verify the user

```php
// --- reset.php

$user = Auth::fetchForPasswordReset($_GET['hash']);
```    
