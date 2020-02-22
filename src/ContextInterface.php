<?php

declare(strict_types=1);

namespace Jasny\Auth;

/**
 * Entity used as context for auth.
 */
interface ContextInterface
{
    /**
     * Get context id.
     */
    public function getAuthId(): ?string;
}
