<?php

namespace Jasny\Auth;

/**
 * Authorization is supported
 */
interface Authorization
{
    /**
     * Check if user had specified role.
     * 
     * @param mixed $role
     * @return boolean
     */
    public static function authorize($role);
}
