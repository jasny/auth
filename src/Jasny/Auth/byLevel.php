<?php

namespace Jasny\Auth;

/**
 * Authorize by access level.
 */
trait byLevel
{
    /**
     * Authorization levels.
     * Level names should not contain only digits.
     * 
     * @var array
     */
    protected static $levels;
    
    
    /**
     * Get all access levels.
     *  
     * @return array
     */
    public static function getLevels()
    {
        if (!isset(static::$levels)) {
            trigger_error("Auth levels aren't set", E_USER_WARNING);
            return [];
        }
        
        return static::$levels;
    }
    
    /**
     * Get access level
     * 
     * @param string $type
     * @return int
     */
    public static function getLevel($type)
    {
        $level = array_search($type, static::$levels);
        if ($level === false) throw new \Exception("Authorization level '$type' isn't defined.");
        
        return $level;
    }

    /**
     * Check if user has specified access level or more.
     * 
     * @param int $level
     * @return boolean
     */
    public static function forLevel($level)
    {
        if ($level === 0) return true;
        if (!static::user()) return false;
        
        if (is_string($level) && !ctype_digit($level)) $level = static::getLevel($level);
        
        $role = static::user()->getRole();
        if (is_string($role) && !ctype_digit($role))$role = static::getLevel($role);
        
        return $role >= $level;
    }
}
