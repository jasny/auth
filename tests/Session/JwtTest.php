<?php

declare(strict_types=1);

namespace Jasny\Auth\Tests\Session;

use DateInterval;
use DateTimeImmutable;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Validation\Constraint;
use Jasny\Auth\Session\Jwt;
use Jasny\Auth\Session\Jwt\CookieValue;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Jasny\Auth\Session\Jwt
 * @covers \Jasny\Auth\Session\Jwt\CookieValue
 */
class JwtTest extends TestCase
{
    protected Configuration $jwtConfig;
    protected Jwt $jwt;

    public function setUp(): void
    {
        $this->jwtConfig = Configuration::forUnsecuredSigner();

        $constraint = class_exists(Constraint\LooseValidAt::class)
            // V4
            ? new Constraint\LooseValidAt(
                new FrozenClock(new DateTimeImmutable('2020-01-02T00:00:00+00:00')),
                new DateInterval('PT30S')
            )
            // V3
            : new Constraint\ValidAt(
                new FrozenClock(new DateTimeImmutable('2020-01-02T00:00:00+00:00')),
                new DateInterval('PT30S')
            );
        $this->jwtConfig->setValidationConstraints($constraint);

        $this->jwt = (new Jwt($this->jwtConfig))
            ->withCookie(new CookieValue());
    }

    public function testGetInfo()
    {
        $token = $this->jwtConfig->builder()
            ->withClaim('user', 'abc')
            ->withClaim('context', 99)
            ->withClaim('checksum', 'xyz')
            ->withHeader('iat', new \DateTimeImmutable('2020-01-01T00:00:00+00:00'))
            ->issuedAt(new \DateTimeImmutable('2020-01-01T00:00:00+00:00'))
            ->expiresAt(new \DateTimeImmutable('2020-01-03T00:00:00+00:00'))
            ->getToken($this->jwtConfig->signer(), $this->jwtConfig->signingKey());

        $cookie = new CookieValue($token->toString());
        $this->jwt = $this->jwt->withCookie($cookie);

        $info = $this->jwt->getInfo();

        $expected = [
            'user' => 'abc',
            'context' => 99,
            'checksum' => 'xyz',
            'timestamp' => new \DateTimeImmutable('2020-01-01T00:00:00+00:00'),
        ];
        $this->assertEquals($expected, $info);
    }

    public function testGetInfoWithoutTimestamp()
    {
        $token = $this->jwtConfig->builder()
            ->withClaim('user', 'abc')
            ->withClaim('context', 99)
            ->withClaim('checksum', 'xyz')
            ->issuedAt(new \DateTimeImmutable('2020-01-01T00:00:00+00:00'))
            ->getToken($this->jwtConfig->signer(), $this->jwtConfig->signingKey());

        $cookie = new CookieValue($token->toString());

        $this->jwt = $this->jwt->withCookie($cookie);

        $info = $this->jwt->getInfo();

        $expected = [
            'user' => 'abc',
            'context' => 99,
            'checksum' => 'xyz',
            'timestamp' => null,
        ];
        $this->assertEquals($expected, $info);
    }

    public function testGetInfoWithExpiredToken()
    {
        $token = $this->jwtConfig->builder()
            ->withClaim('user', 'abc')
            ->withClaim('context', 99)
            ->withClaim('checksum', 'xyz')
            ->withHeader('iat', new \DateTimeImmutable('2020-01-01T00:00:00+00:00'))
            ->issuedAt(new \DateTimeImmutable('2020-01-01T00:00:00+00:00'))
            ->expiresAt(new \DateTimeImmutable('2020-01-01T12:00:00+00:00'))
            ->getToken($this->jwtConfig->signer(), $this->jwtConfig->signingKey());

        $cookie = new CookieValue($token->toString());
        $this->jwt = $this->jwt->withCookie($cookie);

        $info = $this->jwt->getInfo();

        $this->assertEquals(
            ['user' => null, 'context' => null, 'checksum' => null, 'timestamp' => null],
            $info
        );
    }

    public function testGetInfoDefaults()
    {
        $info = $this->jwt->getInfo();

        $this->assertEquals(
            ['user' => null, 'context' => null, 'checksum' => null, 'timestamp' => null],
            $info
        );
    }

    public function testPersist()
    {
        $timestamp = new \DateTime('2020-01-01T00:00:00+00:00'); // Should convert to DateTimeImmutable

        $cookie = new CookieValue();
        $this->jwt = $this->jwt->withCookie($cookie);

        $this->jwt->persist('abc', 99, 'xyz', $timestamp);

        $token = $this->jwtConfig->builder()
            ->withClaim('user', 'abc')
            ->withClaim('context', 99)
            ->withClaim('checksum', 'xyz')
            ->withHeader('iat', new \DateTimeImmutable('2020-01-01T00:00:00+00:00'))
            ->issuedAt(new \DateTimeImmutable('2020-01-01T00:00:00+00:00'))
            ->expiresAt(new \DateTimeImmutable('2020-01-02T00:00:00+00:00'))
            ->getToken($this->jwtConfig->signer(), $this->jwtConfig->signingKey());

        $this->assertEquals($token->toString(), $cookie->get());
        $this->assertEquals(strtotime('2020-01-02T00:00:00+00:00'), $cookie->getExpire());
    }

    public function testClear()
    {
        $token = $this->jwtConfig->builder()
            ->withClaim('user', 'abc')
            ->withClaim('context', 99)
            ->withClaim('checksum', 'xyz')
            ->withHeader('iat', new \DateTimeImmutable('2020-01-01T00:00:00+00:00'))
            ->issuedAt(new \DateTimeImmutable('2020-01-01T00:00:00+00:00'))
            ->getToken($this->jwtConfig->signer(), $this->jwtConfig->signingKey());

        $cookie = new CookieValue($token->toString());
        $this->jwt = $this->jwt->withCookie($cookie);

        $this->jwt->clear();

        $this->assertNull($cookie->get());
        $this->assertEquals(1, $cookie->getExpire());
    }

    public function testTtl()
    {
        $timestamp = new \DateTime('2020-01-01T00:00:00+00:00'); // Should convert to DateTimeImmutable

        $cookie = new CookieValue();
        $this->jwt = $this->jwt
            ->withTtl(3600)
            ->withCookie($cookie);

        $this->jwt->persist('abc', 99, 'xyz', $timestamp);

        $token = $this->jwtConfig->builder()
            ->withClaim('user', 'abc')
            ->withClaim('context', 99)
            ->withClaim('checksum', 'xyz')
            ->withHeader('iat', new \DateTimeImmutable('2020-01-01T00:00:00+00:00'))
            ->issuedAt(new \DateTimeImmutable('2020-01-01T00:00:00+00:00'))
            ->expiresAt(new \DateTimeImmutable('2020-01-01T01:00:00+00:00'))
            ->getToken($this->jwtConfig->signer(), $this->jwtConfig->signingKey());

        $this->assertEquals($token->toString(), $cookie->get());
        $this->assertEquals(strtotime('2020-01-01T01:00:00+00:00'), $cookie->getExpire());
    }
}
