<?php

namespace Jasny\Authz;

use Jasny\Authz\User;

/**
 * Authorize by access group.
 * Can be used for ACL (Access Control List).
 * 
 * <code>
 *   class Auth extends Jasny\Auth
 *   {
 *     use Jasny\Authz\ByGroup;
 *
 *     protected function getGroupStructure()
 *     {
 *       return [
 *         'user' => [],
 *         'accountant' => ['user'],
 *         'moderator' => ['user'],
 *         'developer' => ['user'],
 *         'admin' => ['moderator', 'developer']
 *       ];
 *     }
 *   }
 * </code>
 */
trait ByGroup
{
    /**
     * Get the authenticated user
     * 
     * @return User
     */
    abstract public function user();
    
    /**
     * Get the groups and the groups it supersedes.
     * 
     * @return array
     */
    abstract protected function getGroupStructure();
    
    
    /**
     * Get group and all groups it supersedes (recursively).
     *  
     * @param string|array $group  Single group or array of groups
     * @return array
     */
    protected function expandGroup($group)
    {
        $groups = (array)$group;
        $structure = $this->getGroupStructure();

        $expanded = [];
        
        foreach ($groups as $group) {
            if (!isset($structure[$group])) {
                continue;
            }
            
            $expanded[] = $group;
            $expanded = array_merge($expanded, $this->expandGroup((array)$structure[$group]));
        }
        
        return array_unique($expanded);
    }
    
    
    /**
     * Get all auth roles
     *  
     * @return array
     */
    public function getRoles()
    {
        $structure = $this->getGroupStructure();
        
        if (!is_array($structure)) {
            throw new \UnexpectedValueException("Group structure should be an array");
        }
        
        return array_keys($structure);
    }
    
    /**
     * Check if the current user is logged in and has specified role.
     * 
     * <code>
     *   if (!$auth->is('manager')) {
     *     http_response_code(403); // Forbidden
     *     echo "You are not allowed to view this page";
     *     exit();
     *   }
     * </code>
     * 
     * @param string $group
     * @return boolean
     */
    public function is($group)
    {
        if (!in_array($group, $this->getRoles())) {
            trigger_error("Unknown role '$group'", E_USER_NOTICE);
            return false;
        }
        
        $user = $this->user();
        
        if (!isset($user)) {
            return false;
        }
        
        $userGroups = $this->expandGroup($user->getRole());
        
        return in_array($group, $userGroups);
    }
}
