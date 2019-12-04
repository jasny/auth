<?php

declare(strict_types=1);

namespace Jasny\Auth\Authz;

use Jasny\Auth\AuthzInterface as Authz;
use Jasny\Auth\ContextInterface as Context;
use Jasny\Auth\UserInterface as User;
use Jasny\Immutable;

/**
 * Trait for keeping state (user and context) in authz service.
 */
trait StateTrait
{
    use Immutable\With;

    /**
     * Current authenticated user
     */
    protected ?User $user = null;

    /**
     * The authorization context. This could be an organization, where a user has specific roles per organization
     * rather than roles globally.
     */
    protected ?Context $context = null;

    /**
     * Get a copy of the service for the given user.
     *
     * @param User|null $user
     * @return static&Authz
     */
    public function forUser(?User $user): Authz
    {
        return $this->withProperty('user', $user);
    }

    /**
     * Get a copy of the service for the given context.
     * Returns $this if authz hasn't changed.
     *
     * @param Context|null $context
     * @return static&Authz
     */
    public function inContextOf(?Context $context): Authz
    {
        return $this->withProperty('context', $context);
    }

    /**
     * Get current authenticated user.
     *
     * @return User|null
     */
    final public function user(): ?User
    {
        return $this->user;
    }

    /**
     * Get the current context.
     */
    final public function context(): ?Context
    {
        return $this->context;
    }

}
