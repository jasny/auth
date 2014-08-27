<?php

namespace Jasny\Auth;

/**
 * Authorize by access group.
 * Can be used for ACL (Access Control List).
 */
trait byGroup
{
    /**
     * Authorization groups
     * @var array
     */
    protected static $groups;
    
    
    /**
     * Get all auth groups
     *  
     * @return array
     */
    public static function getGroups()
    {
        if (!isset(static::$groups)) {
            trigger_error("Auth groups aren't set", E_USER_WARNING);
            return [];
        }
        
        return static::$groups;
    }
    
    /**
     * Check if user has specified auth group or more.
     * 
     * @param int $group
     * @return boolean
     */
    public static function forGroup($group)
    {
        if (!self::user()) return false;
        
        $roles = self::user()->getRole();
        
        foreach ($roles as $role) {
            $roles[]
        }
    }
}
