<?php

namespace Jasny;

/**
 * Authorization
 */
interface Authz
{
    /**
     * Get all authz roles
     *  
     * @return array
     */
    public function getRoles();
    
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
     * @param string $role
     * @return boolean
     */
    public function is($role);
}
