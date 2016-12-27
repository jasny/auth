<?php

namespace Jasny;

use Jasny\Auth\User;

/**
 * Authentication and access control
 * 
 * <code>
 * class Auth extends Jasny\Auth
 * {
 *     use Jasny\Auth\ByLevel;
 *     use Jasny\Auth\Sessions;
 * 
 *     protected $levels = [
 *       'user' => 1,
 *       'admin' => 10
 *     ];
 * 
 *     public function fetchUserById($id)
 *     {
 *         ...
 *     }
 * 
 *     public function fetchUserByUsername($username)
 *     {
 *         ...
 *     }
 * }
 * </code>
 */
abstract class Auth
{
    /**
     * Current authenticated user
     * @var User|false
     */
    protected $user;
    
    
    /**
     * Persist the current user id across requests
     * 
     * @return void
     */
    abstract protected function persistCurrentUser();
    
    /**
     * Get current authenticated user id
     * 
     * @return mixed
     */
    abstract protected function getCurrentUserId();
    
    /**
     * Fetch a user by ID
     * 
     * @param int|string $id
     * @return User|null
     */
    abstract public function fetchUserById($id);

    /**
     * Fetch a user by username
     * 
     * @param string $username
     * @return User|null
     */
    abstract public function fetchUserByUsername($username);
    
    
    /**
     * Get current authenticated user
     * 
     * @return User|null
     */
    public function user()
    {
        if (!isset($this->user)) {
            $uid = $this->getCurrentUserId();
            $this->user = $uid ? ($this->fetchUserById($uid) ?: false) : false;
        }
        
        return $this->user ?: null;
    }
    
    /**
     * Set the current user
     * 
     * @param User|null $user
     * @return User|null
     */
    public function setUser(User $user)
    {
        if ($user->onLogin() === false) {
            return null;
        }
        
        $this->user = $user;
        $this->persistCurrentUser();
        
        return $this->user;
    }
    
    
    /**
     * Hash a password
     * 
     * @param string $password
     * @return string
     */
    public function hashPassword($password)
    {
        if (!is_string($password) || $password === '') {
            throw new \InvalidArgumentException("Password should be a (non-empty) string");
        }
        
        return password_hash($password, PASSWORD_BCRYPT);
    }
    
    /**
     * Fetch user and verify credentials.
     * 
     * @param User|null $user
     * @param string    $password
     * @return boolean
     */
    public function verifyCredentials($user, $password)
    {
        return isset($user) && password_verify($password, $user->getHashedPassword());
    }
    
    /**
     * Login with username and password
     * 
     * @param string $username
     * @param string $password
     * @return User|null
     */
    public function login($username, $password)
    {
        $user = $this->fetchUserByUsername($username);

        if (!$this->verifyCredentials($user, $password)) {
            return null;
        }
        
        return $this->setUser($user);
    }
    
    /**
     * Logout
     */
    public function logout()
    {
        $user = $this->user();
        
        if (!$user) {
            return;
        }
        
        $user->onLogout();
        
        $this->user = false;
        $this->persistCurrentUser();
    }
}
