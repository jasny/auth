<?php

declare(strict_types=1);

namespace Jasny\Auth\Event;

use Psr\EventDispatcher\StoppableEventInterface;

/**
 * Called when user logs in.
 */
class Login extends AbstractEvent implements StoppableEventInterface
{
    use CancellableTrait;
}
