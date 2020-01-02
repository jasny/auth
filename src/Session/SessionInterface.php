<?php

declare(strict_types=1);

namespace Jasny\Auth\Session;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Session service for authorization.
 */
interface SessionInterface
{
    /**
     * Get a copy of the service for the PSR-7 server request.
     *
     * @return static
     */
    public function forRequest(ServerRequestInterface $request): self;

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
