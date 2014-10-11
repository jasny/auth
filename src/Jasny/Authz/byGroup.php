<?php

namespace Jasny\Authz;

/**
 * Authorize by access group.
 * Can be used for ACL (Access Control List).
 * 
 * IMPORTANT: Your user class also needs to implement Jasny\Authz\User
 * <code>
 *   class User implements Jasny\Auth\User, Jasny\Authz\User
 *   {
 *     ...
 *   
 *     public function hasRole($role)
 *     {
 *       return in_array($role, Auth::expandGroup($this->group));
 *     }
 *   }
 * </code>
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
     * @param string|array $groups
     * @return array
     */
    public static function expandGroup($groups)
    {
        if (!is_array($groups)) $groups = (array)$groups;
        
        $expanded = $groups;
        
        foreach ($groups as $group) {
            if (!empty(self::$groups[$group])) {
                $groups = array_merge($groups, static::expandGroup(self::$groups[$group]));
            }
        }
        
        return array_unique($expanded);
    }
}
