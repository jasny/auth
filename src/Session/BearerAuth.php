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
     * Get auth information.
     *
     * @return array{uid:string|null,context:mixed,checksum:string|null}
     */
    public function getInfo(): array
    {
        $token = stripos($this->header, 'bearer ') === 0
            ? trim(substr($this->header, 6))
            : '';

        if ($token === '') {
            return ['uid' => null, 'context' => null, 'checksum' => null];
        }

        return [
            'uid' => sprintf($this->idFormat, $token),
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
