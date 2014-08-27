<?php

namespace Jasny\Auth;

/**
 * Methods for a record supporting authentication
 */
interface User
{
    /**
     * Get user id
     * 
     * @return mixed
     */
    public function getId();
    
    /**
     * Get user's username
     * 
     * @return string
     */
    public function getUsername();
    
    /**
     * Get user's hashed password
     * 
     * @return string
     */
    public function getPassword();
    
    /**
     * Get authentication level or group(s).
     * 
     * @internal Return level (int) or level name (string) for level based auth.
     * @internal Return group (string) or groups (array) for group base auth.
     * 
     * @return int|string|array
     */
    public function getRole();
    
    
    /**
     * Event called on login.
     * 
     * @return boolean  false cancels the login
     */
    public function onLogin();
    
    /**
     * Event called on logout.
     */
    public function onLogout();
}
