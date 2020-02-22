<?php

declare(strict_types=1);

namespace Jasny\Auth\Tests\User;

use Jasny\Auth\ContextInterface as Context;
use Jasny\Auth\UserInterface as User;
use Jasny\Auth\User\PartiallyLoggedIn;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\MockObject\MockObject;

/**
 * @covers \Jasny\Auth\User\PartiallyLoggedIn
 */
class PartiallyLoggedInTest extends TestCase
{
    protected PartiallyLoggedIn $wrapper;

    /** @var User&MockObject  */
    protected $user;

    public function setUp(): void
    {
        $this->user = $this->createMock(User::class);
        $this->wrapper = new PartiallyLoggedIn($this->user);
    }

    public function testGetUser()
    {
        $this->assertSame($this->user, $this->wrapper->getUser());
    }


    public function testGetAuthId()
    {
        $this->user->expects($this->once())->method('getAuthId')->willReturn('42');

        $this->assertEquals('#partial:42', $this->wrapper->getAuthId());
    }

    public function testVerifyPassword()
    {
        $this->user->expects($this->once())->method('verifyPassword')
            ->with('foo')
            ->willReturn(true);

        $this->assertTrue($this->wrapper->verifyPassword('foo'));
    }

    public function testGetAuthRole()
    {
        $context = $this->createMock(Context::class);

        $this->user->expects($this->once())->method('getAuthRole')
            ->with($this->identicalTo($context))
            ->willReturn('user');

        $this->assertEquals('user', $this->wrapper->getAuthRole($context));
    }

    public function testGetAuthChecksum()
    {
        $this->user->expects($this->once())->method('getAuthChecksum')->willReturn('abc');

        $this->assertEquals('abc', $this->wrapper->getAuthChecksum());
    }

    public function testRequiresMFA()
    {
        $this->user->expects($this->never())->method('requiresMFA');

        $this->assertTrue($this->wrapper->requiresMFA());
    }
}
