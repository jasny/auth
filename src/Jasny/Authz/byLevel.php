<?php

namespace Jasny\Authz;

/**
 * Authorize by access level.
 * 
 * IMPORTANT: Your user class also needs to implement Jasny\Authz\User
 * <code>
 *   class User implements Jasny\Auth\User, Jasny\Authz\User
 *   {
 *     ...
 *   
 *     public function hasRole($role)
 *     {
 *       return Auth::getLevel($role) &lt;= $this->accessLevel;
 *     }
 *   }
 * </code>
 */
trait byLevel
{
    /**
     * Authorization levels.
     * Level names should not contain only digits.
     * 
     * <code>
     *   protected static $levels = [
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
}
