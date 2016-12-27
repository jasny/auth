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
     * @param string $subject
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
     * Generate a confirm checksum based on a user id and secret.
     * 
     * For more entropy overwrite this method:
     * <code>
     *   protected function getConfirmationChecksum($id, $len = 32)
     *   {
     *     return parent::getConfirmationChecksum($id, $len);
     *   }
     * </code>
     * 
     * @param string $id
     * @param int    $len  The number of characters of the hash (max 64)
     * @return int
     */
    protected function getConfirmationChecksum($id, $len = 16)
    {
        $hash = hash('sha256', $id . $this->getConfirmationSecret());
        return substr($hash, 0, $len);
    }
    
    /**
     * Generate a confirmation token
     * 
     * @param User    $user
     * @param string  $subject      What needs to be confirmed?
     * @param boolean $usePassword  Use password hash in checksum
     * @return string
     */
    public function getConfirmationToken(User $user, $subject, $usePassword = false)
    {
        $hashids = $this->createHashids($subject);
        
        $id = $user->getId();
        $pwd = $usePassword ? $user->getHashedPassword() : '';
        
        $confirm = $this->getConfirmationChecksum($id . $pwd);
        
        return $hashids->encodeHex($confirm . $id);
    }
    
    /**
     * Get user by confirmation hash
     * 
     * @param string $token    Confirmation token
     * @param string $subject  What needs to be confirmed?
     * @param boolean $usePassword  Use password hash in checksum
     * @return User|null
     */
    public function fetchUserForConfirmation($token, $subject, $usePassword = false)
    {
        $hashids = $this->createHashids($subject);
        
        $idAndConfirm = $hashids->decodeHex($token);
        
        if (empty($idAndConfirm)) {
            return null;
        }
        
        $len = strlen($this->getConfirmationChecksum(''));
        $id = substr($idAndConfirm, $len);
        $confirm = substr($idAndConfirm, 0, $len);
        
        $user = $this->fetchUserById($id);

        if (!isset($user)) {
            return null;
        }
        
        $pwd = $usePassword ? $user->getHashedPassword() : '';
        
        if ($confirm !== $this->getConfirmationChecksum($id . $pwd)) {
            return null;
        }
        
        return $user;
    }
}
