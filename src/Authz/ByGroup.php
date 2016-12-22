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
 *     protected $groups = [
 *       'user' => [],
 *       'developer' => ['user'],
 *       'accountant' => ['user'],
 *       'admin' => ['developer', 'accountant']
 *     ];
 *   }
 * </code>
 */
trait ByGroup
{
    /**
     * Authentication groups
     * @internal Overwrite this in your child class
     * 
     * @var string[]
     */
    protected $groups = [
        'user' => []
    ];
    
    /**
     * Get all auth groups
     *  
     * @return array
     */
    public function getGroups()
    {
        return $this->groups;
    }
    
    /**
     * Get group and all groups it embodies.
     *  
     * @param string|array $groups  Single group or array of groups
     * @return array
     */
    public function expandGroup($groups)
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
