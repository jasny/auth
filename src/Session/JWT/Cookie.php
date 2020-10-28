<?php

declare(strict_types=1);

namespace Jasny\Auth\Session\JWT;

/**
 * Use global $_COOKIE and setcookie() for the JWT cookie.
 */
class Cookie implements CookieInterface
{
    protected string $name;
    protected int $ttl;
    protected string $path;
    protected string $domain;
    protected bool $secure;
    protected bool $httpOnly;

    /**
     * Cookies constructor.
     */
    public function __construct(
        string $name = 'jwt',
        string $path = '',
        string $domain = '',
        bool $secure = false,
        bool $httpOnly = true
    ) {
        $this->name = $name;
        $this->path = $path;
        $this->domain = $domain;
        $this->secure = $secure;
        $this->httpOnly = $httpOnly;
    }

    /**
     * @inheritDoc
     */
    public function get(): ?string
    {
        return $_COOKIE[$this->name] ?? null;
    }

    /**
     * @inheritDoc
     */
    public function set(string $value, int $expire): void
    {
        $success = setcookie($this->name, $value, $expire, $this->domain, $this->path, $this->secure, $this->httpOnly);

        if (!$success) {
            throw new \RuntimeException("Failed to set cookie '{$this->name}'");
        }

        $_COOKIE[$this->name] = $value;
    }

    /**
     * @inheritDoc
     */
    public function clear(): void
    {
        $success = setcookie($this->name, '', 1, $this->domain, $this->path, $this->secure, $this->httpOnly);

        if (!$success) {
            throw new \RuntimeException("Failed to clear cookie '{$this->name}'");
        }

        unset($_COOKIE[$this->name]);
    }
}
