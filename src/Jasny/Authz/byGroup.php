<?php

namespace Jasny\Authz;

/**
 * Authorize by access group.
 * Can be used for ACL (Access Control List).
 * 
 * <code>
 *   class Auth extends Jasny\Auth
 *   {
 *     use Jasny\Authz\ByGroup;
 *
 *     protected static $groups = [
 *       'user' => [],
 *       'developer' => ['user'],
 *       'accountant' => ['user'],
 *       'admin' => ['developer', 'accountant']
 *     ];
 *   }
 * </code>
 *
 * IMPORTANT: Your User class also needs to implement Jasny\Authz\User
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
     * @param string|array $groups  Single group or array of groups
     * @return array
     */
    public static function expandGroup($groups)
    {
        if (!is_array($groups)) $groups = (array)$groups;
        
        $allGroups = static::getGroups();
        $expanded = $groups;
        
        foreach ($groups as $group) {
            if (!empty($allGroups[$group])) {
                $expanded = array_merge($groups, static::expandGroup($allGroups[$group]));
            }
        }
        
        return array_unique($expanded);
    }
}
