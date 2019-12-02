<?php

declare(strict_types=1);

namespace Jasny\Auth;

/**
 * Entity used for as user for auth.
 */
interface UserInterface
{
    /**
     * Get user id
     *
     * @return int|string
     */
    public function getId();

    /**
     * Get user's hashed password.
     */
    public function verifyPassword(string $password): bool;

    /**
     * Get checksum/hash for critical user data like username, e-mail, and password.
     * If the checksum changes, the user is logged out in all sessions.
     */
    public function getAuthChecksum(): string;

    /**
     * Get the role(s) of the user.
     *
     * @param mixed $context
     * @return int|string|int[]|string[]
     */
    public function getRole($context = null);
}
