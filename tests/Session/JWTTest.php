<?php

declare(strict_types=1);

namespace Jasny\Auth\Tests\Session;

use Jasny\Auth\Session\JWT;
use Jasny\Auth\Session\JWT\CookieValue;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\ValidationData;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Jasny\Auth\Session\JWT
 * @covers \Jasny\Auth\Session\JWT\CookieValue
 */
class JWTTest extends TestCase
{
    protected Builder $builder;
    protected JWT $jwt;

    public function setUp(): void
    {
        $this->builder = new Builder();

        $this->jwt = (new JWT($this->builder,  new ValidationData()))
            ->withCookie(new CookieValue());
    }

    public function testGetInfo()
    {
        $token = $this->builder
            ->withClaim('user', 'abc')
            ->withClaim('context', 99)
            ->withClaim('checksum', 'xyz')
            ->issuedAt(strtotime('2020-01-01T00:00:00+00:00'), true)
            ->getToken();

        $cookie = new CookieValue((string)$token);
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
        $token = $this->builder
            ->withClaim('user', 'abc')
            ->withClaim('context', 99)
            ->withClaim('checksum', 'xyz')
            ->issuedAt(strtotime('2020-01-01T00:00:00+00:00'), false)
            ->getToken();

        $cookie = new CookieValue((string)$token);

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
        $token = $this->builder
            ->withClaim('user', 'abc')
            ->withClaim('context', 99)
            ->withClaim('checksum', 'xyz')
            ->issuedAt(strtotime('2020-01-01T00:00:00+00:00'), true)
            ->expiresAt(strtotime('2020-01-02T00:00:00+00:00'))
            ->getToken();

        $cookie = new CookieValue((string)$token);
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
        $timestamp = new \DateTimeImmutable('2020-01-01T00:00:00+00:00');

        $cookie = new CookieValue();
        $this->jwt = $this->jwt->withCookie($cookie);

        $this->jwt->persist('abc', 99, 'xyz', $timestamp);

        $token = $this->builder
            ->withClaim('user', 'abc')
            ->withClaim('context', 99)
            ->withClaim('checksum', 'xyz')
            ->issuedAt(strtotime('2020-01-01T00:00:00+00:00'), true)
            ->expiresAt(strtotime('2020-01-02T00:00:00+00:00'))
            ->getToken();

        $this->assertEquals((string)$token, $cookie->get());
        $this->assertEquals(strtotime('2020-01-02T00:00:00+00:00'), $cookie->getExpire());
    }

    public function testClear()
    {
        $token = $this->builder
            ->withClaim('user', 'abc')
            ->withClaim('context', 99)
            ->withClaim('checksum', 'xyz')
            ->issuedAt(strtotime('2020-01-01T00:00:00+00:00'), true)
            ->getToken();

        $cookie = new CookieValue((string)$token);
        $this->jwt = $this->jwt->withCookie($cookie);

        $this->jwt->clear();

        $this->assertNull($cookie->get());
        $this->assertEquals(1, $cookie->getExpire());
    }

    public function testTtl()
    {
        $timestamp = new \DateTimeImmutable('2020-01-01T00:00:00+00:00');

        $cookie = new CookieValue();
        $this->jwt = $this->jwt
            ->withTtl(3600)
            ->withCookie($cookie);

        $this->jwt->persist('abc', 99, 'xyz', $timestamp);

        $token = $this->builder
            ->withClaim('user', 'abc')
            ->withClaim('context', 99)
            ->withClaim('checksum', 'xyz')
            ->issuedAt(strtotime('2020-01-01T00:00:00+00:00'), true)
            ->expiresAt(strtotime('2020-01-01T01:00:00+00:00'))
            ->getToken();

        $this->assertEquals((string)$token, $cookie->get());
        $this->assertEquals(strtotime('2020-01-01T01:00:00+00:00'), $cookie->getExpire());
    }

    public function testWithCustomParser()
    {
        $token = $this->builder
            ->withClaim('user', 'abc')
            ->withClaim('context', 99)
            ->withClaim('checksum', 'xyz')
            ->issuedAt(strtotime('2020-01-01T00:00:00+00:00'), true)
            ->getToken();

        $cookie = new CookieValue('..TOKEN..');

        $parser = $this->createMock(Parser::class);
        $parser->expects($this->once())->method('parse')
            ->with('..TOKEN..')
            ->willReturn($token);

        $this->jwt = $this->jwt
            ->withParser($parser)
            ->withCookie($cookie);

        $info = $this->jwt->getInfo();

        $expected = [
            'user' => 'abc',
            'context' => 99,
            'checksum' => 'xyz',
            'timestamp' => new \DateTimeImmutable('2020-01-01T00:00:00+00:00'),
        ];
        $this->assertEquals($expected, $info);
    }
}
