<?php

declare(strict_types=1);

namespace Jasny\Auth\Session;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Use OOP abstracted sessions to store auth session info.
 */
class SessionObject implements SessionInterface
{
    use GetInfoTrait;

    protected string $key;

    /** @var \ArrayAccess<string,mixed> */
    protected \ArrayAccess $session;

    /**
     * Service constructor.
     *
     * @param \ArrayAccess<string,mixed> $session
     * @param string                     $key
     */
    public function __construct(\ArrayAccess $session, string $key = 'auth')
    {
        $this->session = $session;
        $this->key = $key;
    }

    /**
     * Use the `session` attribute if it's an object that implements ArrayAccess.
     *
     * @return self
     */
    public function forRequest(ServerRequestInterface $request): self
    {
        $session = $request->getAttribute('session');

        if (!$session instanceof \ArrayAccess) {
            return $this;
        }

        $copy = clone $this;
        $copy->session = $session;

        return $copy;
    }


    /**
     * @inheritDoc
     */
    public function getInfo(): array
    {
        return $this->getInfoFromData($this->session[$this->key] ?? []);
    }

    /**
     * @inheritDoc
     */
    public function persist($userId, $contextId, ?string $checksum, ?\DateTimeInterface $timestamp): void
    {
        $this->session[$this->key] = [
            'user' => $userId,
            'context' => $contextId,
            'checksum' => $checksum,
            'timestamp' => isset($timestamp) ? $timestamp->getTimestamp() : null,
        ];
    }

    /**
     * Remove auth information from session.
     */
    public function clear(): void
    {
        if (isset($this->session[$this->key])) {
            unset($this->session[$this->key]);
        }
    }
}
