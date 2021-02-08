<?php

declare(strict_types=1);

namespace Jasny\Auth\Session;

use DateTimeImmutable;
use Jasny\Auth\Session\Jwt\Cookie;
use Jasny\Auth\Session\Jwt\CookieInterface;
use Jasny\Immutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\UnencryptedToken;

/**
 * Use JSON Web Token and JSON Web Signature (RFC 7519) to store auth session info.
 *
 * @see https://github.com/lcobucci/jwt
 */
class Jwt implements SessionInterface
{
    use Immutable\With;

    protected Configuration $jwtConfig;

    protected int $ttl = 24 * 3600;
    protected CookieInterface $cookie;

    /**
     * JWT constructor.
     */
    public function __construct(Configuration $jwtConfig)
    {
        $this->jwtConfig = $jwtConfig;
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
     * @inheritDoc
     */
    public function getInfo(): array
    {
        $jwt = $this->cookie->get();

        /** @var (Token&UnencryptedToken)|null $token */
        $token = $jwt !== null && $jwt !== ''
            ? $this->jwtConfig->parser()->parse($jwt)
            : null;

        $constraints = $this->jwtConfig->validationConstraints();

        if ($token === null ||
            ($constraints !== [] && !$this->jwtConfig->validator()->validate($token, ...$constraints))
        ) {
            return ['user' => null, 'context' => null, 'checksum' => null, 'timestamp' => null];
        }

        $timestamp = $token->headers()->get('iat');
        if (is_array($timestamp)) {
            $timestamp = new \DateTimeImmutable($timestamp['date'], new \DateTimeZone($timestamp['timezone']));
        }

        return [
            'user' => $token->claims()->get('user'),
            'context' => $token->claims()->get('context'),
            'checksum' => $token->claims()->get('checksum'),
            'timestamp' => $timestamp,
        ];
    }

    /**
     * @inheritDoc
     */
    public function persist($userId, $contextId, ?string $checksum, ?\DateTimeInterface $timestamp): void
    {
        $builder = clone $this->jwtConfig->builder();

        if ($timestamp instanceof \DateTime) {
            $timestamp = \DateTimeImmutable::createFromMutable($timestamp);
        }
        /** @var DateTimeImmutable|null $timestamp */
        $time = $timestamp ?? new \DateTimeImmutable();
        $expire = $time->add(new \DateInterval("PT{$this->ttl}S"));

        $builder
            ->withClaim('user', $userId)
            ->withClaim('context', $contextId)
            ->withClaim('checksum', $checksum)
            ->issuedAt($time)
            ->expiresAt($expire);

        if ($timestamp !== null) {
            $builder->withHeader('iat', $timestamp);
        }

        $this->cookie->set(
            $builder->getToken($this->jwtConfig->signer(), $this->jwtConfig->signingKey())->toString(),
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
