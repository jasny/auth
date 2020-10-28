<?php

declare(strict_types=1);

namespace Jasny\Auth\Session\JWT;

/**
 * Interface for the JWT cookie.
 */
interface CookieInterface
{
    /**
     * Get the value of the cookie.
     *
     * @return string|null
     */
    public function get(): ?string;

    /**
     * Set the cookie.
     */
    public function set(string $value, int $expire): void;

    /**
     * Remove the cookie.
     */
    public function clear(): void;
}
