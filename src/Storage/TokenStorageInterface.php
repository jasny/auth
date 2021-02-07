<?php

declare(strict_types=1);

namespace Jasny\Auth\Storage;

use Jasny\Auth\StorageInterface;
use Jasny\Auth\UserInterface;

/**
 * Interface for storage that can save and fetch by user token.
 */
interface TokenStorageInterface extends StorageInterface
{
    /**
     * Save a confirmation token to the database.
     */
    public function saveToken(UserInterface $user, string $subject, string $token, \DateTimeInterface $expire): void;

    /**
     * Fetch a user by a confirmation token.
     *
     * @phpstan-return array{uid:string,expire:\DateTimeInterface}|null
     */
    public function fetchToken(string $subject, string $token): ?array;
}
