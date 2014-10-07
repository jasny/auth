<?php

namespace Jasny\Auth;

/**
 * Don't persist the authenticated user
 */
trait NoSessions
{
    /**
     * Don't persist
     */
    protected static function persistCurrentUser()
    { }
    
    /**
     * There is never a persisted user id
     * 
     * @return null
     */
    protected static function getCurrentUserId()
    {
        return null;
    }
}
