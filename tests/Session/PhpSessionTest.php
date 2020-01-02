<?php

namespace Jasny\Auth\Tests\Session;

use Jasny\Auth\Session\PhpSession;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Jasny\Auth\Session\PhpSession
 */
class PhpSessionTest extends TestCase
{
    protected PhpSession $service;

    public function setUp(): void
    {
        $this->service = new PhpSession();
        session_start();
    }

    public function tearDown(): void
    {
        if (session_status() === \PHP_SESSION_ACTIVE) {
            session_destroy();
        }
    }


    public function testGetInfo()
    {
        $_SESSION['auth'] = ['user' => 'abc', 'context' => 99, 'checksum' => 'xyz', 'foo' => 'bar'];

        $info = $this->service->getInfo();
        $this->assertEquals(['user' => 'abc', 'context' => 99, 'checksum' => 'xyz'], $info);
    }

    public function testGetInfoDefaults()
    {
        $info = $this->service->getInfo();
        $this->assertEquals(['user' => null, 'context' => null, 'checksum' => null], $info);
    }

    public function testPersist()
    {
        $this->service->persist('abc', 99, 'xyz');

        $this->assertArrayHasKey('auth', $_SESSION);
        $this->assertEquals($_SESSION['auth'], ['user' => 'abc', 'context' => 99, 'checksum' => 'xyz']);
    }

    public function testClear()
    {
        $_SESSION['auth'] = ['user' => 'abc', 'context' => 99, 'checksum' => 'xyz'];

        $this->service->clear();
        $this->assertArrayNotHasKey('auth', $_SESSION);
    }


    public function expectSessionNotStarted()
    {
        session_destroy();

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage("Unable to use session for auth info: Session not started");
    }

    public function testGetInfoWithoutActiveSession()
    {
        $this->expectSessionNotStarted();
        $this->service->getInfo();
    }

    public function testPersistWithoutActiveSession()
    {
        $this->expectSessionNotStarted();
        $this->service->persist('abc', 99, 'xyz');
    }

    public function testClearWithoutActiveSession()
    {
        $this->expectSessionNotStarted();
        $this->service->clear();
    }

}
