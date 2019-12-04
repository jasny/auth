<?php

declare(strict_types=1);

namespace Jasny\Auth\Tests;

use Jasny\Auth\Confirmation\NoConfirmation;
use Jasny\Auth\StorageInterface;
use Jasny\Auth\UserInterface as User;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Jasny\Auth\Confirmation\NoConfirmation
 */
class NoConfirmationTest extends TestCase
{
    protected NoConfirmation $service;

    public function setUp(): void
    {
        $this->service = new NoConfirmation();
    }

    public function testWithSubject()
    {
        $this->assertSame($this->service, $this->service->withSubject('test'));
    }

    public function testWithStorage()
    {
        /** @var StorageInterface $storage */
        $storage = $this->createMock(StorageInterface::class);

        $this->assertSame($this->service, $this->service->withStorage($storage));
    }

    public function testGetToken()
    {
        /** @var User&MockObject $user */
        $user = $this->createMock(User::class);

        $this->expectException(\LogicException::class);
        $this->service->getToken($user, new \DateTimeImmutable());
    }

    public function testFrom()
    {
        $this->expectException(\LogicException::class);
        $this->service->from('abc');
    }
}
