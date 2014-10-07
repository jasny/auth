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
     * <code>
     *   protected static $groups = [
     *     'user' => 1,
     *     'moderator' => 100,
     *     'admin' => 1000
     *   ];
     * </code>
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
     * @param string $name  Level name
     * @return int
     */
    public static function getLevel($name)
    {
        $levels = static::getLevels();
        if (!isset($levels[$name])) throw new \Exception("Authorization level '$name' isn't defined.");
        
        return $levels[$name];
    }

    /**
     * Check if user has specified access level or more.
     * 
     * @param int|string $level
     * @return boolean
     */
    public static function authorize($level)
    {
        if ($level === 0) return true;
        if (!static::user()) return false;
        
        if (is_string($level) && !ctype_digit($level)) $level = static::getLevel($level);
        
        $role = static::user()->getRole();
        if (is_string($role) && !ctype_digit($role)) $role = static::getLevel($role);
        
        return $role >= $level;
    }
}
