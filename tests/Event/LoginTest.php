<?php

declare(strict_types=1);

namespace Jasny\Auth\Tests\Event;

use Jasny\Auth\Auth;
use Jasny\Auth\Event\Login;
use Jasny\Auth\UserInterface as User;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Jasny\Auth\Event\Login
 * @covers \Jasny\Auth\Event\AbstractEvent
 */
class LoginTest extends TestCase
{
    public function testGetEmitter()
    {
        $auth = $this->createMock(Auth::class);
        $user = $this->createMock(User::class);

        $login = new Login($auth, $user);

        $this->assertSame($auth, $login->getEmitter());
    }

    public function testGetUser()
    {
        $auth = $this->createMock(Auth::class);
        $user = $this->createMock(User::class);

        $login = new Login($auth, $user);

        $this->assertSame($user, $login->getUser());
    }

    public function testCancel()
    {
        $auth = $this->createMock(Auth::class);
        $user = $this->createMock(User::class);

        $login = new Login($auth, $user);

        $this->assertFalse($login->isCancelled());
        $this->assertFalse($login->isPropagationStopped());
        $this->assertEquals('', $login->getCancellationReason());

        $login->cancel('not ok');

        $this->assertTrue($login->isCancelled());
        $this->assertTrue($login->isPropagationStopped());
        $this->assertEquals('not ok', $login->getCancellationReason());
    }
}
