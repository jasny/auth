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
     * Get authentication level
     * 
     * @return int
     */
    public function getAuthLevel();
    
    
    /**
     * Event called on login.
     * 
     * @return boolean  false cancels the login
     */
    public function onLogin();
}
