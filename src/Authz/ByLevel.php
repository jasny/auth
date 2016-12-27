<?php

namespace Jasny\Authz;

/**
 * Authorize by access level.
 * 
 * <code>
 *   class Auth extends Jasny\Auth
 *   {
 *     use Jasny\Authz\ByLevel;
 *
 *     protected function getAccessLevels()
 *     {
 *       return [
 *         'user' => 1,
 *         'moderator' => 100,
 *         'admin' => 1000
 *       ];
 *     }
 *   }
 * </code>
 */
trait ByLevel
{
    /**
     * Get the authenticated user
     * 
     * @return User
     */
    abstract public function user();
    
    /**
     * Get all access levels.
     *  
     * @return array
     */
    abstract protected function getAccessLevels();
    
    /**
     * Get access level by name.
     * 
     * @param string|int $role
     * @return int
     * @throws DomainException for unknown level names
     */
    public function getLevel($role)
    {
        if (is_int($role) || (is_string($role) && ctype_digit($role))) {
            return (int)$role;
        }
        
        if (!is_string($role)) {
            $type = (is_object($role) ? get_class($role) . ' ' : '') . gettype($role);
            throw new \InvalidArgumentException("Expected role to be a string, not a $type");
        }
        
        $levels = $this->getAccessLevels();
        
        if (!isset($levels[$role])) {
            throw new \DomainException("Authorization level '$role' isn't defined.");
        }
        
        return $levels[$role];
    }
    
    /**
     * Get all authz roles
     *  
     * @return array
     */
    public function getRoles()
    {
        $levels = $this->getAccessLevels();
        
        if (!is_array($levels)) {
            throw new \UnexpectedValueException("Access levels should be an array");
        }
        
        return array_keys($levels);
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
     * @param string|int $role
     * @return boolean
     */
    public function is($role)
    {
        if (!in_array($role, $this->getRoles())) {
            trigger_error("Unknown role '$role'", E_USER_NOTICE);
            return false;
        }
        
        $user = $this->user();
        
        if (!isset($user)) {
            return false;
        }
        
        try {
            $userLevel = $this->getLevel($user->getRole());
        } catch (\DomainException $ex) {
            trigger_error("Unknown user role '" . $user->getRole() . "'", E_USER_NOTICE);
            return false;
        } catch (\Exception $ex) {
            trigger_error($ex->getMessage(), E_USER_WARNING);
            return false;
        } 
        
        return $userLevel >= $this->getLevel($role);
    }
}
