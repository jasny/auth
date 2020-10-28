<?php

declare(strict_types=1);

namespace Jasny\Auth\Session\JWT;

/**
 * Temporary store of the JWT cookie.
 */
class CookieValue implements CookieInterface
{
    protected ?string $value;
    protected int $expire = 0;

    /**
     * Cookies constructor.
     */
    public function __construct(?string $value = null)
    {
        $this->value = $value;
    }

    /**
     * @inheritDoc
     */
    public function get(): ?string
    {
        return $this->value;
    }

    /**
     * @inheritDoc
     */
    public function set(string $value, int $expire): void
    {
        $this->value = $value;
        $this->expire = $expire;
    }

    /**
     * @inheritDoc
     */
    public function clear(): void
    {
        $this->value = null;
        $this->expire = 1;
    }

    /**
     * Get expire time for the cookie.
     */
    public function getExpire(): int
    {
        return $this->expire;
    }
}
