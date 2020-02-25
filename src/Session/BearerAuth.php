<?php

declare(strict_types=1);

namespace Jasny\Auth\Session;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Get auth info from Bearer Authorization header
 */
class BearerAuth implements SessionInterface
{
    protected string $idFormat;
    protected string $header;

    /**
     * Service constructor.
     */
    public function __construct(?ServerRequestInterface $request = null, string $idFormat = '%s')
    {
        $this->idFormat = $idFormat;
        $this->header = isset($request)
            ? ($request->getHeaderLine('Authorization') ?? '')
            : ($_SERVER['HTTP_AUTHORIZATION'] ?? '');
    }

    /**
     * @inheritDoc
     */
    public function getInfo(): array
    {
        $token = stripos($this->header, 'bearer ') === 0
            ? trim(substr($this->header, 6))
            : '';

        return $token === ''
            ? ['user' => null, 'context' => null, 'checksum' => null, 'timestamp' => null]
            : ['user' => sprintf($this->idFormat, $token), 'context' => null, 'checksum' => '', 'timestamp' => null];
    }


    /**
     * @inheritDoc
     * @throws \LogicException Since bearer authorization can't be modified server side.
     */
    public function persist($userId, $contextId, ?string $checksum, ?\DateTimeInterface $timestamp): void
    {
        throw new \LogicException("Unable to persist auth info when using bearer authorization");
    }

    /**
     * @throws \LogicException Since bearer authorization can't be modified server side.
     */
    public function clear(): void
    {
        throw new \LogicException("Unable to persist auth info when using bearer authorization");
    }
}
