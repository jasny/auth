<?php

declare(strict_types=1);

namespace Jasny\Auth\Session;

/**
 * Use PHP sessions to store auth session info.
 */
class PhpSession implements SessionInterface
{
    protected string $key;

    /**
     * Service constructor.
     *
     * @param string $key
     */
    public function __construct(string $key = 'auth')
    {
        $this->key = $key;
    }

    /**
     * Assert that there is an active session.
     *
     * @throws \RuntimeException if there is no active session
     */
    protected function assertSessionStarted(): void
    {
        if (session_status() !== \PHP_SESSION_ACTIVE) {
            throw new \RuntimeException("Unable to use session for auth info: Session not started");
        }
    }

    /**
     * Get auth information from session.
     *
     * @return array{user:mixed,context:mixed,checksum:string|null}
     */
    public function getInfo(): array
    {
        $this->assertSessionStarted();

        $data = $_SESSION[$this->key] ?? [];

        return [
            'user' => $data['user'] ?? null,
            'context' => $data['context'] ?? null,
            'checksum' => $data['checksum'] ?? null,
        ];
    }

    /**
     * Persist auth information to session.
     *
     * @param mixed       $userId
     * @param mixed       $contextId
     * @param string|null $checksum
     */
    public function persist($userId, $contextId, ?string $checksum): void
    {
        $this->assertSessionStarted();

        $_SESSION[$this->key] = ['user' => $userId, 'context' => $contextId, 'checksum' => $checksum];
    }

    /**
     * Remove auth information from session.
     */
    public function clear(): void
    {
        $this->assertSessionStarted();

        unset($_SESSION[$this->key]);
    }
}
