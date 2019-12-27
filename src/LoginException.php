<?php

declare(strict_types=1);

namespace Jasny\Auth;

/**
 * Exception on failed login attempt.
 */
class LoginException extends AuthException
{
    public const CANCELLED = 0;
    public const INVALID_CREDENTIALS = 1;
}
