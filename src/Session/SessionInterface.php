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
     * @return array{uid:string|int|null,context:mixed,checksum:string|null}
     */
    public function getInfo(): array;

    /**
     * Persist auth information to session.
     *
     * @param string|int  $uid
     * @param mixed       $context
     * @param string|null $checksum
     */
    public function persist($uid, $context, ?string $checksum): void;

    /**
     * Remove auth information from session.
     */
    public function clear(): void;
}
