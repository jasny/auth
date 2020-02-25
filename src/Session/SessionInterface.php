<?php

declare(strict_types=1);

namespace Jasny\Auth\Session;

/**
 * Session service for authorization.
 */
interface SessionInterface
{
    /**
     * Get auth information from session.
     *
     * @return array{user:mixed,context:mixed,checksum:string|null,timestamp:\DateTimeInterface|null}
     */
    public function getInfo(): array;

    /**
     * Persist auth information to session.
     *
     * @param mixed                   $userId
     * @param mixed                   $contextId
     * @param string|null             $checksum
     * @param \DateTimeInterface|null $timestamp
     */
    public function persist($userId, $contextId, ?string $checksum, ?\DateTimeInterface $timestamp): void;

    /**
     * Remove auth information from session.
     */
    public function clear(): void;
}
