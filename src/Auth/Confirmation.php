<?php

namespace Jasny\Auth;

use Hashids\Hashids;

/**
 * Generate and verify a hash to confirm a new user.
 * 
 * Uses the hashids library
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
     * Generate a confirm hash based on a user id
     * 
     * @param string $id
     * @return string
     */
    protected function generateConfirmHash($id)
    {
        $confirmHash = hash('sha256', $id . $this->getConfirmationSecret());
        
        return sprintf('%012s', substr(base_convert($confirmHash, 16, 36), -12));
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
        if (!class_exists(Hashids::class)) {
            throw new \Exception("Unable to generate a confirmation hash: Hashids library is not installed");
        }
        
        $id = $user->getId();
        $confirm = $this->generateConfirmHash($id);
        
        $salt = hash('sha256', $this->getConfirmationSecret());
        $hashids = new Hashids($salt);
        
        $decId = hexdec($id); // Will work if id is hexidecimal or decimal
        
        return $hashids->encode($subject, $decId, $confirm);
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
        if (!class_exists(Hashids::class)) {
            throw new \Exception("Unable to generate a confirmation hash: Hashids library is not installed");
        }
        
        $hashids = new Hashids($this->getConfirmationSalt());
        
        list($decId, $tokenSubject, $confirm) = (array)$hashids->decode($token) + [null, null, null];
        
        $id = isset($decId) ? hexdec($decId) : null; // Inverse action of getConfirmationToken
        
        if (!isset($id) || $tokenSubject !== $subject || $confirm !== $this->generateConfirmHash($id)) {
            return null;
        }

        return $this->fetchUserById($id);
    }
}
