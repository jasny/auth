<?php

declare(strict_types=1);

namespace Jasny\Auth\Tests\Confirmation;

use DateTime;
use Jasny\Auth\Confirmation\InvalidTokenException;
use Jasny\Auth\Confirmation\TokenConfirmation;
use Jasny\Auth\Storage\TokenStorageInterface;
use Jasny\Auth\StorageInterface;
use Jasny\Auth\UserInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

/**
 * @covers \Jasny\Auth\Confirmation\TokenConfirmation
 */
class TokenConfirmationTest extends TestCase
{
    /** @var MockObject&TokenStorageInterface */
    protected $storage;

    /** @var MockObject&LoggerInterface */
    protected $logger;

    protected TokenConfirmation $service;

    public function setUp(): void
    {
        $this->storage = $this->createMock(TokenStorageInterface::class);
        $this->logger = $this->createMock(LoggerInterface::class);

        $this->service = (new TokenConfirmation())
            ->withStorage($this->storage)
            ->withLogger($this->logger)
            ->withSubject('test');
    }

    public function testGetToken()
    {
        $user = $this->createMock(UserInterface::class);
        $expire = new DateTime('now + 1 hour');
        $storedToken = null;

        $this->storage->expects($this->once())->method('saveToken')
            ->with(
                $this->identicalTo($user),
                'test',
                $this->callback(function ($token) use (&$storedToken) {
                    $this->assertIsString($token);
                    $this->assertEquals(32, strlen(base_convert($token, 36, 16)));
                    $storedToken = $token;

                    return true;
                }),
                $this->identicalTo($expire)
            );

        $token = $this->service->getToken($user, $expire);

        $this->assertEquals($storedToken, $token);
    }

    public function testFrom()
    {
        $user = $this->createMock(UserInterface::class);
        $expire = new DateTime('now + 1 hour');
        $token = '0123456789abcdef';

        $this->storage->expects($this->once())->method('fetchToken')
            ->with('test', $token)
            ->willReturn(['uid' => '42', 'expire' => $expire]);

        $this->storage->expects($this->once())->method('fetchUserById')
            ->with('42')
            ->willReturn($user);

        $result = $this->service->from($token);

        $this->assertSame($user, $result);
    }

    public function testFromWithUnknownToken()
    {
        $user = $this->createMock(UserInterface::class);
        $token = 'abcd';

        $this->storage->expects($this->once())->method('fetchToken')
            ->with('test', $token)
            ->willReturn(null);

        $this->logger->expects($this->once())->method('debug')
            ->with('Unknown confirmation token', ['token' => $token]);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage("Token has been revoked");

        $result = $this->service->from($token);

        $this->assertSame($user, $result);
    }

    public function testFromWithExpiredToken()
    {
        $user = $this->createMock(UserInterface::class);
        $expire = new DateTime('now - 1 hour');
        $token = '0123456789abcdef';

        $this->storage->expects($this->once())->method('fetchToken')
            ->with('test', $token)
            ->willReturn(['uid' => '42', 'expire' => $expire]);

        $this->logger->expects($this->once())->method('debug')
            ->with('Expired confirmation token', ['token' => $token, 'uid' => '42']);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage("Token is expired");

        $result = $this->service->from($token);

        $this->assertSame($user, $result);
    }

    public function testFromWithUnkownUser()
    {
        $user = $this->createMock(UserInterface::class);
        $expire = new DateTime('now + 1 hour');
        $token = '0123456789abcdef';

        $this->storage->expects($this->once())->method('fetchToken')
            ->with('test', $token)
            ->willReturn(['uid' => '999', 'expire' => $expire]);

        $this->logger->expects($this->once())->method('debug')
            ->with('Invalid confirmation token: user not available', ['token' => $token, 'uid' => '999']);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage("Token has been revoked");

        $result = $this->service->from($token);

        $this->assertSame($user, $result);
    }


    public function testStorageNotSetGetToken()
    {
        $user = $this->createMock(UserInterface::class);
        $expire = new DateTime('now + 1 hour');

        $this->expectException(\BadMethodCallException::class);

        (new TokenConfirmation())->getToken($user, $expire);
    }

    public function testStorageNotSetFrom()
    {
        $this->expectException(\BadMethodCallException::class);

        (new TokenConfirmation())->from('abc');
    }

    public function testSetUnsupportedStorage()
    {
        $storage = $this->createMock(StorageInterface::class);

        $this->expectException(\InvalidArgumentException::class);

        (new TokenConfirmation())->withStorage($storage);
    }
}
