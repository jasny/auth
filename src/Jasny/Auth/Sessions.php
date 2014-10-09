<?php

namespace Jasny\Auth;

/**
 * Use PHP sessions to persist the authenticated user
 */
trait Sessions
{
    /**
     * Store the current user id in the session
     */
    protected static function persistCurrentUser()
    {
        if (static::$user) {
            $_SESSION['auth_uid'] = static::$user->getId();
        } else {
            unset($_SESSION['auth_uid']);
        }
    }
    
    /**
     * Get current authenticated user id for the session
     * 
     * @return mixed
     */
    protected static function getCurrentUserId()
    {
        return isset($_SESSION['auth_uid']) ? $_SESSION['auth_uid'] : null;
    }
}
