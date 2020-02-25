<?php

namespace Jasny\Auth\Tests\Session;

use Jasny\Auth\Session\PhpSession;
use Jasny\PHPUnit\ExpectWarningTrait;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Jasny\Auth\Session\PhpSession
 */
class PhpSessionTest extends TestCase
{
    use ExpectWarningTrait;

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
        $_SESSION['auth'] = [
            'user' => 'abc',
            'context' => 99,
            'checksum' => 'xyz',
            'foo' => 'bar',
            'timestamp' => strtotime('2020-01-01T00:00:00+00:00'),
        ];

        $date = new \DateTimeImmutable('2020-01-01T00:00:00+00:00');

        $info = $this->service->getInfo();
        $this->assertEquals(['user' => 'abc', 'context' => 99, 'checksum' => 'xyz', 'timestamp' => $date], $info);
    }

    public function testGetInfoWithoutTimestamp()
    {
        $_SESSION['auth'] = [
            'user' => 'abc',
            'context' => 99,
            'checksum' => 'xyz',
            'foo' => 'bar',
        ];

        $info = $this->service->getInfo();
        $this->assertEquals(['user' => 'abc', 'context' => 99, 'checksum' => 'xyz', 'timestamp' => null], $info);
    }

    public function testGetInfoWithInvalidTimestamp()
    {
        $_SESSION['auth'] = [
            'user' => 'abc',
            'context' => 99,
            'checksum' => 'xyz',
            'foo' => 'bar',
            'timestamp' => 'INVALID DATE',
        ];

        $this->expectWarningMessage("DateTimeImmutable::__construct(): Failed to parse time string (@INVALID DATE) "
            . "at position 0 (@): Unexpected character");

        $info = $this->service->getInfo();

        $this->assertEquals(['user' => 'abc', 'context' => 99, 'checksum' => 'xyz', 'timestamp' => null], $info);
    }

    public function testGetInfoDefaults()
    {
        $info = $this->service->getInfo();
        $this->assertEquals(['user' => null, 'context' => null, 'checksum' => null, 'timestamp' => null], $info);
    }

    public function testPersist()
    {
        $date = new \DateTimeImmutable('2020-01-01T00:00:00+00:00');

        $this->service->persist('abc', 99, 'xyz', $date);

        $expected = [
            'user' => 'abc',
            'context' => 99,
            'checksum' => 'xyz',
            'timestamp' => strtotime('2020-01-01T00:00:00+00:00'),
        ];

        $this->assertArrayHasKey('auth', $_SESSION);
        $this->assertEquals($expected, $_SESSION['auth']);
    }

    public function testClear()
    {
        $_SESSION['auth'] = ['user' => 'abc', 'context' => 99, 'checksum' => 'xyz', 'timestamp' => null];

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
        $this->service->persist('abc', 99, 'xyz', null);
    }

    public function testClearWithoutActiveSession()
    {
        $this->expectSessionNotStarted();
        $this->service->clear();
    }

}
