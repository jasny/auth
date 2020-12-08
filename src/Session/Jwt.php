<?php

declare(strict_types=1);

namespace Jasny\Auth\Session;

use Jasny\Auth\Session\Jwt\Cookie;
use Jasny\Auth\Session\Jwt\CookieInterface;
use Jasny\Immutable;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Signer;
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
    protected Signer $signer;
    protected Signer\Key $key;

    protected Parser $parser;
    protected ValidationData $validation;

    protected int $ttl = 24 * 3600;
    protected CookieInterface $cookie;

    /**
     * JWT constructor.
     */
    public function __construct(Builder $builder, Signer $signer, Signer\Key $key, ValidationData $validation)
    {
        $this->builder = $builder;
        $this->signer = $signer;
        $this->key = $key;

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
            'user' => $token->claims()->get('user'),
            'context' => $token->claims()->get('context'),
            'checksum' => $token->claims()->get('checksum'),
            'timestamp' => $token->headers()->get('iat'),
        ];
    }

    /**
     * @inheritDoc
     */
    public function persist($user, $context, ?string $checksum, ?\DateTimeInterface $timestamp): void
    {
        $builder = clone $this->builder;

        if ($timestamp instanceof \DateTime) {
            $timestamp = \DateTimeImmutable::createFromMutable($timestamp);
        }
        $time = $timestamp ?? new \DateTimeImmutable();
        $expire = $time->add(new \DateInterval("PT{$this->ttl}S"));

        $builder
            ->withClaim('user', $user)
            ->withClaim('context', $context)
            ->withClaim('checksum', $checksum)
            ->issuedAt($time)
            ->expiresAt($expire);

        if ($timestamp !== null) {
            $builder->withHeader('iat', $timestamp);
        }

        $this->cookie->set(
            (string)$builder->getToken($this->signer, $this->key),
            $expire->getTimestamp()
        );
    }

    /**
     * @inheritDoc
     */
    public function clear(): void
    {
        $this->cookie->clear();
    }
}
