<?php

namespace Jasny;

use Jasny\Auth\User;
use Jasny\Auth\Fetching;

/**
 * Authentication and access control
 * 
 * <code>
 * class MyAuth extends Jasny\Auth
 * {
 *     use Jasny\Auth\Sessions;
 * 
 *     public static function fetchUserById($id)
 *     {
 *         ...
 *     }
 * 
 *     public static function fetchUserByUsername($username)
 *     {
 *         ...
 *     }
 * }
 * </code>
 */
abstract class Auth implements Fetching
{
    /**
     * Secret word for creating a verification hash
     * @var string
     */
    protected static $secret;

    /**
     * Current user
     * @var User
     */
    protected static $user;
    
    
    /**
     * Persist the current user id across requests
     */
    protected static function persistCurrentUser()
    {
        // Black hole
    }
    
    /**
     * Get current authenticated user id
     * 
     * @return mixed
     */
    protected static function getCurrentUserId()
    {
        return null;
    }
    
    
    /**
     * Generate a password
     * 
     * @param string $password
     * @param string $salt      Use specific salt to verify existing password
     */
    public static function password($password, $salt=null)
    {
        return isset($salt) ? crypt($password, $salt) : password_hash($password, PASSWORD_BCRYPT);
    }

    
    /**
     * Fetch user and verify password
     * 
     * @return User|false
     */
    public static function verify($username, $password)
    {
        $user = static::fetchUserByUsername($username);
        
        if (!isset($user) || $user->getPassword() !== static::password($password, $user->getPassword())) return false;
        return $user;
    }
    
    /**
     * Login with username and password
     * 
     * @param string $username
     * @param string $password
     * @return boolean
     */
    public static function login($username, $password)
    {
        $user = static::verify($username, $password);
        if (!$user) return null;
        
        return static::setUser($user);
    }
    
    /**
     * Set the current user
     * 
     * @param User $user
     * @return boolean
     */
    public static function setUser(User $user)
    {
        if (!$user->onLogin()) return false;
        
        self::$user = $user;
        static::persistCurrentUser();
        
        return true;
    }
    
    /**
     * Logout
     */
    public static function logout()
    {
        $user = static::user();
        if (!$user) return;
        
        $user->onLogout();
        
        static::$user = null;
        static::persistCurrentUser();
    }
    
    /**
     * Get current authenticated user
     * 
     * @return User
     */
    public static function user()
    {
        if (!isset(static::$user)) {
            $uid = static::getCurrentUserId();
            if ($uid) static::$user = static::fetchUserById($uid);
        }
        
        return static::$user;
    }
    
    /**
     * Check if the current user is logged in and (optionally) had specified role.
     * 
     * <code>
     *   if (!Auth::access('manager')) {
     *     http_response_code(403); // Forbidden
     *     echo "You are not allowed to view this page";
     *     exit();
     *   }
     * </code>
     * 
     * @param mixed $role
     * @return boolean
     */
    public static function access($role = null)
    {
        if (!static::user()) return false;
        if (!isset($role)) return true;

        return static::user() instanceof Authz\User && static::user()->hasRole($role);
    }

    
    /**
     * Get secret word
     * 
     * @return string
     */
    protected static function getSecret()
    {
        if (!isset(static::$secret)) throw new \Exception("Auth secret isn't set");
        return static::$secret;
    }
    
    /**
     * Generate a confirmation hash
     * 
     * @param User $user
     * @return string
     */
    public static function generateConfirmationHash($user)
    {
        $id = $user->getId();
        
        return sprintf('%010s', substr(base_convert(md5($id . static::getSecret()), 16, 36), -10) .
            base_convert($id, 10, 36));
    }
    
    /**
     * Get user by confirmation hash
     * 
     * @parma string $hash  confirmation hash
     * @return User
     */
    public static function fetchForConfirmation($hash)
    {
        $id = base_convert(substr($hash, 10), 36, 10);
        if (static::generateConfirmationHash($id) != $hash) return null; // invalid hash
        
        return static::fetchUserById($id);
    }
    
    /**
     * Generate a hash to reset the password
     * 
     * @param User $user
     * @return string
     */
    public static function generatePasswordResetHash($user)
    {
        $id = $user->getId();
        $password = $user->getPassword();
        
        return sprintf('%010s', substr(base_convert(md5($id . static::getSecret() . $password), 16, 36), -10)
            . base_convert($id, 10, 36));
    }
    
    /**
     * Fetch a user for a password reset
     * 
     * @param string $hash
     * @return User
     */
    public static function fetchForPasswordReset($hash)
    {
        $id = base_convert(substr($hash, 10), 36, 10);
        
        $user = static::fetchUserById($id);
        if (!$user || static::generatePasswordResetHash($id, $user->getPassword()) != $hash) return null; // invalid hash
        
        return $user;
    }
}
