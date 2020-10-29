<?php

declare(strict_types=1);

namespace Jasny\Auth\Session;

use Jasny\Auth\Session\Jwt\Cookie;
use Jasny\Auth\Session\Jwt\CookieInterface;
use Jasny\Immutable;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\ValidationData;

/**
 * Use JSON Web Token and JSON Web Signature (RFC 7519) to store auth session info.
 *
 * @see https://github.com/lcobucci/jwt
 */
class Jwt implements SessionInterface
{
    use Immutable\With;

    protected Builder $builder;
    protected Parser $parser;
    protected ValidationData $validation;

    protected int $ttl = 24 * 3600;
    protected CookieInterface $cookie;

    /**
     * JWT constructor.
     */
    public function __construct(Builder $builder, ValidationData $validation)
    {
        $this->builder = $builder;
        $this->validation = $validation;
        $this->parser = new Parser();

        $this->cookie = new Cookie('jwt');
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
    public function withCookie(CookieInterface $cookie): self
    {
        return $this->withProperty('cookie', $cookie);
    }

    /**
     * Get a copy with a custom JWT parser.
     */
    public function withParser(Parser $parser): self
    {
        return $this->withProperty('parser', $parser);
    }

    /**
     * @inheritDoc
     */
    public function getInfo(): array
    {
        $jwt = $this->cookie->get();

        $token = $jwt !== null && $jwt !== ''
            ? $this->parser->parse($jwt)
            : null;

        if ($token === null || !$token->validate($this->validation)) {
            return ['user' => null, 'context' => null, 'checksum' => null, 'timestamp' => null];
        }

        return [
            'user' => $token->getClaim('user'),
            'context' => $token->getClaim('context'),
            'checksum' => $token->getClaim('checksum'),
            'timestamp' => $token->hasHeader('iat')
                ? (new \DateTimeImmutable())->setTimestamp($token->getHeader('iat'))
                : null,
        ];
    }

    /**
     * @inheritDoc
     */
    public function persist($user, $context, ?string $checksum, ?\DateTimeInterface $timestamp): void
    {
        $builder = clone $this->builder;

        $time = isset($timestamp) ? $timestamp->getTimestamp() : time();
        $expire = $time + $this->ttl;

        $token = $builder
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
