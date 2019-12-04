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
    protected User $user;

    /**
     * AbstractEvent constructor.
     */
    public function __construct(Auth $_, User $user)
    {
        $this->user = $user;
    }

    /**
     * Get the user.
     */
    final public function user(): User
    {
        return $this->user;
    }
}
