<?php

namespace Jasny\Authz;

/**
 * Entity used for authorization
 */
interface User
{
    /**
     * Get the role(s) of the user.
     * 
     * @return int|string|string[]
     */
    public function getRole();
}
