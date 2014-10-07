<?php

namespace Jasny\Auth;

/**
 * Authorize by access group.
 * Can be used for ACL (Access Control List).
 */
trait byGroup
{
    /**
     * Authorization groups and each group is embodies.
     * 
     * <code>
     *   protected static $groups = [
     *     'user' => [],
     *     'developer' => ['user'],
     *     'accountant' => ['user'],
     *     'admin' => ['developer', 'accountant']
     *   ];
     * </code>
     * 
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
     * Get group and all groups it embodies.
     *  
     * @return array
     */
    public static function expandGroup($group)
    {
        $groups = [$group];
        
        if (!empty(self::$groups[$group])) {
            foreach (self::$groups[$group] as $sub) {
                $groups = array_merge($groups, static::expandGroup($sub));
            }
            
            $groups = array_unique($groups);
        }
        
        return $groups;
    }
    
    /**
     * Check if user is in specified access group.
     * 
     * @param int $group
     * @return boolean
     */
    public static function authorize($group)
    {
        if (!self::user()) return false;
        
        $roles = self::user()->getRole();
        
        foreach ($roles as $role) {
            $roles = array_merge($roles, self::expandGroup($role));
        }

        return in_array($group, $roles);
    }
}
