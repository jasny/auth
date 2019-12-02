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
    protected Auth $emitter;
    protected User $user;

    /**
     * AbstractEvent constructor.
     */
    public function __construct(Auth $emitter, User $user)
    {
        $this->emitter = $emitter;
        $this->user = $user;
    }

    /**
     * Get the event emitter.
     */
    final public function getEmitter(): Auth
    {
        return $this->emitter;
    }

    /**
     * Get the event payload.
     */
    final public function getUser(): User
    {
        return $this->user;
    }
}
