<?php

namespace Jasny\Auth;

/**
 * Methods that need to be implemented for fetching user info
 */
interface Fetching
{
    /**
     * Fetch a user by ID
     * 
     * @param int $id
     * @return User
     */
    public static function fetchUserById($id);

    /**
     * Fetch a user by username
     * 
     * @param string $username
     * @return User
     */
    public static function fetchUserByUsername($username);
}
