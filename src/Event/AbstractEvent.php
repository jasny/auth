<?php

declare(strict_types=1);

namespace Jasny\Auth\Event;

use Jasny\Auth\Auth;
use Jasny\Auth\UserInterface as User;

/**
 * Base class for all auth events.
 */
abstract class AbstractEvent
{
    protected Auth $auth;
    protected User $user;

    /**
     * AbstractEvent constructor.
     */
    public function __construct(Auth $auth, User $user)
    {
        $this->auth = $auth;
        $this->user = $user;
    }

    /**
     * Get the Auth service.
     */
    final public function auth(): Auth
    {
        return $this->auth;
    }

    /**
     * Get the user.
     */
    final public function user(): User
    {
        return $this->user;
    }
}
