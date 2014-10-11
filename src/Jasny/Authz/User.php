<?php

namespace Jasny\Authz;

/**
 * Entity used for authorization
 */
interface User
{
    /**
     * Check if user had specified role.
     * 
     * @param string|int $role
     * @return boolean
     */
    public static function hasRole($role);
}
