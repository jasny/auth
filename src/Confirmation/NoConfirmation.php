<?php

declare(strict_types=1);

namespace Jasny\Auth\Confirmation;

use Jasny\Auth\StorageInterface as Storage;
use Jasny\Auth\UserInterface as User;

/**
 * No support for confirmation tokens.
 */
class NoConfirmation implements ConfirmationInterface
{
    /**
     * Get copy with storage service.
     *
     * @param Storage $storage
     * @return static
     */
    public function withStorage(Storage $storage)
    {
        return $this;
    }

    /**
     * Create a copy of this service with a specific subject.
     *
     * @param string $subject
     * @return static
     */
    public function withSubject(string $subject)
    {
        return $this;
    }

    /**
     * Generate a confirmation token.
     *
     * @throws \LogicException
     */
    public function getToken(User $user, \DateTimeInterface $expire): string
    {
        throw new \LogicException("Confirmation tokens are not supported");
    }

    /**
     * Get user by confirmation token.
     *
     * @param string $token Confirmation token
     * @return User
     * @throws \LogicException
     */
    public function from(string $token): User
    {
        throw new \LogicException("Confirmation tokens are not supported");
    }
}
