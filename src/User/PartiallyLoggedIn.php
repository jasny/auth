<?php

declare(strict_types=1);

namespace Jasny\Auth\User;

use Jasny\Auth\ContextInterface;
use Jasny\Auth\UserInterface;

/**
 * Wrapper for user that is partially logged in.
 */
final class PartiallyLoggedIn implements UserInterface
{
    protected UserInterface $user;

    /**
     * Class constructor.
     *
     * @param UserInterface $user
     */
    public function __construct(UserInterface $user)
    {
        $this->user = $user;
    }

    /**
     * Get wrapper user.
     *
     * @return UserInterface
     */
    public function getUser(): UserInterface
    {
        return $this->user;
    }

    /**
     * @inheritDoc
     */
    public function getAuthId(): string
    {
        return '#partial:' . $this->user->getAuthId();
    }

    /**
     * @inheritDoc
     */
    public function verifyPassword(string $password): bool
    {
        return $this->user->verifyPassword($password);
    }

    /**
     * @inheritDoc
     */
    public function getAuthChecksum(): string
    {
        return $this->user->getAuthChecksum();
    }

    /**
     * @inheritDoc
     */
    public function getAuthRole(?ContextInterface $context = null): string
    {
        return $this->user->getAuthRole($context);
    }

    /**
     * @inheritDoc
     */
    public function requiresMFA(): bool
    {
        return true;
    }
}
