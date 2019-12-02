<?php

declare(strict_types=1);

namespace Jasny\Auth\Confirmation;

/**
 * Exception thrown if the confirmation token isn't valid or is expired.
 */
class InvalidTokenException extends \RuntimeException
{
}
