<?php

declare(strict_types=1);

namespace Jasny\Auth;

use Jasny\Auth\ContextInterface as Context;

/**
 * Entity used for as user for auth.
 */
interface UserInterface
{
    /**
     * Get user id
     *
     * @return string
     */
    public function getAuthId(): string;

    /**
     * Verify that the password matches.
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
     * @param Context|null $context
     * @return int|string|int[]|string[]
     */
    public function getAuthRole(?Context $context = null);

    /**
     * User requires Multi Factor Authentication.
     */
    public function requiresMFA(): bool;
}
