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

You also need to specify how the current user is persisted across requests. If you want to use normal PHP sessions, you
can simply use the `Auth\Sessions` trait.

```php
class Auth extends Jasny\Auth
{
    use Auth\Sessions;

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

    /**
     * Event called on logout.
     */
    public function onLogout()
    {
        $this->last_logout = new DateTime();
        $this->save();
    }
}
```

### Authorization
By default the `Auth` class only does authentication. Authorization can be added by impelmenting the `authorize`
method.

Two traits are predefined to do Authorization: `Authz\byLevel` and `Authz\byGroup`.

#### by level
The `Authz\byLevel` traits implements authorization based on access levels. Each user get permissions for it's level and
all levels below.

```php
class Auth extends Jasny\Auth implements Jasny\Auth\Authorization
{
    use Jasny\Authz\byLevel;

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
}
```

For authorization the user object also needs to implement `Jasny\Authz\User`, adding the `hasRole()` method.

    /**
     * Check if the user has the specified security level
     * 
     * @param int $level
     * @return boolean
     */
    public function hasRole($level)
    {
        return $this->security_level >= $level;
    }

#### by group
The `Auth\byGroup` traits implements authorization using access groups. An access group may supersede other groups.

```php
class Auth extends Jasny\Auth implements Jasny\Auth\Authorization
{
    use Jasny\Authz\byGroup;

    /**
     * Authorization groups and each group is supersedes.
     * @var array
     */
    protected static $groups = [
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

For authorization the user object also needs to implement `Jasny\Authz\User`, adding the `hasRole()` method.

    /**
     * Check if the user is in the specified security group
     * 
     * @param string $group
     * @return boolean
     */
    public function hasRole($group)
    {
        return in_array($group, Auth::expandGroup($this->group));
    }


Usage
---

### Authentication

Verify username and password

    Auth::verify($username, $password);

Login with username and password

    Auth::login($username, $password);

Set user without verification

    Auth::setUser($user);

Logout

    Auth::logout();

Get current user

    Auth::user();


### Authorization

Check if user is allowed to do something

    if (!Auth::authorized('admin')) die("Not allowed");


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
