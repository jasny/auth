<?php

declare(strict_types=1);

namespace Jasny\Auth\Tests\Confirmation;

use DateTime;
use Jasny\Auth\Confirmation\TokenConfirmation;
use Jasny\Auth\Confirmation\TokenStorageInterface;
use Jasny\Auth\UserInterface;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Jasny\Auth\Confirmation\TokenConfirmation
 */
class TokenConfirmationTest extends TestCase
{
    /** @var MockObject&TokenStorageInterface */
    protected $storage;

    protected TokenConfirmation $service;

    public function setUp(): void
    {
        $this->storage = $this->createMock(TokenStorageInterface::class);
        $this->service = (new TokenConfirmation())
            ->withStorage($this->storage)
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
                    $this->assertEquals(16, strlen(base64_decode($token)));
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
        $token = base64_encode(str_repeat("\0", 16));

        $this->storage->expects($this->once())->method('fetchToken')
            ->with('test', $token)
            ->willReturn(['uid' => '42', 'expire' => $expire]);

        $this->storage->expects($this->once())->method('fetchUserById')
            ->with('42')
            ->willReturn($user);

        $result = $this->service->from($token);

        $this->assertSame($user, $result);
    }
}
