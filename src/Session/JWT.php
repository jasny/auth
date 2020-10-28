<?php

declare(strict_types=1);

namespace Jasny\Auth\Session;

use Jasny\Auth\Session\JWT\Cookie;
use Jasny\Immutable;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\ValidationData;

/**
 * Use JSON Web Token and JSON Web Signature (RFC 7519) to store auth session info.
 *
 * @see https://github.com/lcobucci/jwt
 */
class JWT implements SessionInterface
{
    use Immutable\With;

    protected Builder $builder;
    protected ValidationData $validation;

    protected int $ttl;
    protected Cookie $cookie;

    /**
     * JWT constructor.
     */
    public function __construct(Builder $builder, ValidationData $validation)
    {
        $this->builder = $builder;
        $this->validation = $validation;
    }

    /**
     * Get a copy with a different TTL for expiry.
     */
    public function withTtl(int $seconds): self
    {
        return $this->withProperty('ttl', $seconds);
    }

    /**
     * Get a copy with custom cookie handler.
     */
    public function withCookie(Cookie $cookie): self
    {
        return $this->withProperty('cookie', $cookie);
    }

    /**
     * @inheritDoc
     */
    public function getInfo(): array
    {
        $jwt = $this->cookie->get();

        if ($jwt === null) {
            return [];
        }

        $token = (new Parser())->parse($jwt);

        if (!$token->validate($this->validation)) {
            return [];
        }

        return [
            'user' => $token->getClaim('user'),
            'context' => $token->getClaim('context'),
            'checksum' => $token->getClaim('checksum'),
            'timestamp' => $token->getHeader('iat'),
        ];
    }

    /**
     * @inheritDoc
     */
    public function persist($user, $context, ?string $checksum, ?\DateTimeInterface $timestamp): void
    {
        $time = isset($timestamp) ? $timestamp->getTimestamp() : time();
        $expire = $time + $this->ttl;

        $token = $this->builder
            ->withClaim('user', $user)
            ->withClaim('context', $context)
            ->withClaim('checksum', $checksum)
            ->issuedAt($time, $timestamp !== null)
            ->expiresAt($expire)
            ->getToken();

        $this->cookie->set((string)$token, $expire);
    }

    /**
     * @inheritDoc
     */
    public function clear(): void
    {
        $this->cookie->clear();
    }
}
