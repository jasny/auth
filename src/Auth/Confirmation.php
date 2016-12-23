<?php

namespace Jasny\Auth;

use Hashids\Hashids;

/**
 * Generate and verify confirmation tokens.
 * 
 * Uses the hashids library.
 * @link http://hashids.org/php/
 * 
 * <code>
 * class Auth extends Jasny\Auth
 * {
 *   use Jasny\Auth\Confirmation;
 * 
 *   public function getConfirmationSecret()
 *   {
 *     return "f)lk3sd^92qlj$%f8321*(&lk";
 *   }
 * 
 *   ...
 * }
 * </code>
 */
trait Confirmation
{
    /**
     * Fetch a user by ID
     * 
     * @param int|string $id
     * @return User|null
     */
    abstract public function fetchUserById($id);
    
    /**
     * Get secret for the confirmation hash
     * 
     * @return string
     */
    abstract protected function getConfirmationSecret();

    
    /**
     * Create a heashids interface
     * 
     * @param string $secret
     * @return Hashids
     */
    protected function createHashids($subject)
    {
        if (!class_exists(Hashids::class)) {
            // @codeCoverageIgnoreStart
            throw new \Exception("Unable to generate a confirmation hash: Hashids library is not installed");
            // @codeCoverageIgnoreEnd
        }
        
        $salt = hash('sha256', $this->getConfirmationSecret() . $subject);
        
        return new Hashids($salt);
    }
    
    /**
     * Generate a confirm hash based on a user id
     * 
     * @param string $id
     * @return int
     */
    protected function generateConfirmHash($id)
    {
        $confirmHash = md5($id . $this->getConfirmationSecret());
        
        return hexdec(substr($confirmHash, 0, 8));
    }
    
    /**
     * Generate a confirmation token
     * 
     * @param User   $user
     * @param string $subject  What needs to be confirmed?
     * @return string
     */
    public function getConfirmationToken(User $user, $subject)
    {
        $hashids = $this->createHashids($subject);
        
        $id = $user->getId();
        $confirm = $this->generateConfirmHash($id);
        
        $parts = array_map('hexdec', str_split($id, 8)); // Will work if id is hexidecimal or decimal
        $parts[] = $confirm;
        
        return $hashids->encode($parts);
    }
    
    /**
     * Get user by confirmation hash
     * 
     * @param string $token    Confirmation token
     * @param string $subject  What needs to be confirmed?
     * @return User|null
     */
    public function fetchUserForConfirmation($token, $subject)
    {
        $hashids = $this->createHashids($subject);
        
        $parts = $hashids->decode($token);
        
        if (empty($parts)) {
            return null;
        }
        
        $confirm = array_pop($parts);
        $id = join(array_map('dechex', $parts));
        
        if ($confirm !== $this->generateConfirmHash($id)) {
            return null;
        }

        return $this->fetchUserById($id);
    }
}
