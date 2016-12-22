<?php

namespace Jasny\Authz;

/**
 * Authorize by access level.
 * 
 * <code>
 *   class Auth extends Jasny\Auth
 *   {
 *     use Jasny\Authz\ByLevel;
 *
 *     protected $levels = [
 *       'user' => 1,
 *       'moderator' => 100,
 *       'admin' => 1000
 *     ];
 *   }
 * </code>
 */
trait ByLevel
{
    /**
     * Authorization levels.
     * 
     * NOTE: Level names should not contain only digits.
     * 
     * @var array
     */
    protected $levels = [
        'user' => 1
    ];
    
    
    /**
     * Get all access levels.
     *  
     * @return array
     */
    public function getLevels()
    {
        return $this->levels;
    }
    
    /**
     * Get access level by name.
     * 
     * @param string $name  Level name
     * @return int
     * @throws DomainException for unknown level names
     */
    public function getLevel($name)
    {
        $levels = $this->getLevels();
        if (!isset($levels[$name])) throw new \DomainException("Authorization level '$name' isn't defined.");
        
        return $levels[$name];
    }
}
