<?php

declare(strict_types=1);

namespace Jasny\Auth\Confirmation;

use Jasny\Auth\StorageInterface as Storage;
use Jasny\Auth\UserInterface as User;
use Psr\Log\LoggerInterface as Logger;

/**
 * Generate and verify confirmation tokens.
 */
interface ConfirmationInterface
{
    /**
     * Get copy with storage service.
     *
     * @param Storage $storage
     * @return static
     */
    public function withStorage(Storage $storage);

    /**
     * Get copy with logger.
     *
     * @param Logger $logger
     * @return static
     */
    public function withLogger(Logger $logger);

    /**
     * Create a copy of this service with a specific subject.
     *
     * @param string $subject
     * @return static
     */
    public function withSubject(string $subject);

    /**
     * Generate a confirmation token.
     */
    public function getToken(User $user, \DateTimeInterface $expire): string;

    /**
     * Get user by confirmation token.
     *
     * @param string $token  Confirmation token
     * @return User
     * @throws InvalidTokenException
     */
    public function from(string $token): User;
}
