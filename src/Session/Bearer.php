<?php

declare(strict_types=1);

namespace Jasny\Auth\Session;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Get auth info from Bearer Authorization header
 */
class Bearer implements SessionInterface
{
    protected string $idFormat;
    protected string $header;

    /**
     * Bearer constructor.
     *
     * @param string $idPrefix
     */
    public function __construct(string $idFormat = '%s')
    {
        $this->idFormat = $idFormat;
        $this->header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    }

    /**
     * @inheritDoc
     */
    public function forRequest(ServerRequestInterface $request): SessionInterface
    {
        $copy = clone $this;
        $copy->header = $request->getHeaderLine('Authorization');

        return $copy;
    }

    /**
     * Get auth information.
     *
     * @return array{uid:string|null,context:mixed,checksum:string|null}
     */
    public function getInfo(): array
    {
        $key = stripos($this->header, 'bearer ') === 0
            ? trim(substr($this->header, 6))
            : '';

        if ($key === '') {
            return ['uid' => null, 'context' => null, 'checksum' => null];
        }

        return [
            'uid' => sprintf($this->idFormat, $key),
            'context' => null,
            'checksum' => '',
        ];
    }


    /**
     * Persist auth information to session.
     *
     * @param string|int $uid
     * @param mixed $context
     * @param string|null $checksum
     * @throws \LogicException Since bearer authorization can't be modified server side.
     */
    public function persist($uid, $context, ?string $checksum): void
    {
        throw new \LogicException("Unable to persist auth info when using bearer authorization");
    }

    /**
     * Remove auth information from session.
     *
     * @throws \LogicException Since bearer authorization can't be modified server side.
     */
    public function clear(): void
    {
        throw new \LogicException("Unable to persist auth info when using bearer authorization");
    }
}
