<?php

declare(strict_types=1);

namespace Jasny\Auth\Session;

/**
 * Use PHP sessions to store auth session info.
 */
class PhpSession implements SessionInterface
{
    use GetInfoTrait;

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
     * @inheritDoc
     */
    public function getInfo(): array
    {
        $this->assertSessionStarted();

        return $this->getInfoFromData($_SESSION[$this->key] ?? []);
    }

    /**
     * @inheritDoc
     */
    public function persist($userId, $contextId, ?string $checksum, ?\DateTimeInterface $timestamp): void
    {
        $this->assertSessionStarted();

        $_SESSION[$this->key] = [
            'user' => $userId,
            'context' => $contextId,
            'checksum' => $checksum,
            'timestamp' => isset($timestamp) ? $timestamp->getTimestamp() : null,
        ];
    }

    /**
     * @inheritDoc
     */
    public function clear(): void
    {
        $this->assertSessionStarted();

        unset($_SESSION[$this->key]);
    }
}
