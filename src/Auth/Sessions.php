<?php

namespace Jasny\Auth;

use Jasny\Auth\User;

/**
 * Use PHP sessions to persist the authenticated user
 */
trait Sessions
{
    /**
     * Get the authenticated user
     * 
     * @return User
     */
    abstract public function user();
    
    
    /**
     * Get the session data
     * 
     * @return array
     */
    protected function getSessionData($key)
    {
        return isset($_SESSION[$key]) ? $_SESSION[$key] : null;
    }
    
    /**
     * Update the session
     * 
     * @param string $key
     * @param mixed  $value
     */
    protected function updateSessionData($key, $value)
    {
        if (is_null($value)) {
            unset($_SESSION[$key]);
        } else {
            $_SESSION[$key] = $value;
        }
    }
    
    
    /**
     * Get current authenticated user id for the session
     * 
     * @return mixed
     */
    protected function getCurrentUserId()
    {
        return $this->getSessionData('auth_uid');
    }
    
    /**
     * Store the current user id in the session
     */
    protected function persistCurrentUser()
    {
        $user = $this->user();
        $this->updateSessionData('auth_uid', $user ? $user->getId() : null);
    }
}
