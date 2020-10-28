<?php

declare(strict_types=1);

namespace Jasny\Auth\Session\Jwt;

/**
 * Use global `$_COOKIE` and `setcookie()` for the JWT cookie.
 *
 * @codeCoverageIgnore
 */
class Cookie implements CookieInterface
{
    protected string $name;

    /**
     * Options for `setcookie()`
     * @var array<string,mixed>
     */
    protected array $options;

    /**
     * Cookies constructor.
     *
     * @param string              $name
     * @param array<string,mixed> $options
     */
    public function __construct(string $name, array $options = [])
    {
        $this->name = $name;
        $this->options = array_change_key_case($options, CASE_LOWER);
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
        $success = setcookie($this->name, $value, ['expire' => $expire] + $this->options);

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
        $success = setcookie($this->name, '', ['expire' => 1] +  $this->options);

        if (!$success) {
            throw new \RuntimeException("Failed to clear cookie '{$this->name}'");
        }

        unset($_COOKIE[$this->name]);
    }
}
