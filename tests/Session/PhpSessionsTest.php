<?php

namespace Jasny\Auth\Tests;

use Jasny\Auth\Session\PhpSession;
use PHPStan\Testing\TestCase;

/**
 * @covers \Jasny\Auth\Session\PhpSession
 */
class PhpSessionsAuth extends TestCase
{
    protected \ArrayObject $session;
    protected PhpSession $service;

    public function setUp(): void
    {
        $this->session = new \ArrayObject();
        $this->service = new PhpSession('auth', $this->session);
    }

    public function testGetInfo()
    {
        $data = ['uid' => 'abc', 'context' => 99, 'checksum' => 'xyz'];
        $this->session['auth'] = $data + ['other' => 'q'];

        $info = $this->service->getInfo();
        $this->assertEquals($data, $info);
    }

    public function testGetInfoDefaults()
    {
        $info = $this->service->getInfo();
        $this->assertEquals(['uid' => null, 'context' => null, 'checksum' => null], $info);
    }

    public function testPersist()
    {
        $this->service->persist('abc', 99, 'xyz');

        $this->assertArrayHasKey('auth', $this->session->getArrayCopy());
        $this->assertEquals($this->session['auth'], ['uid' => 'abc', 'context' => 99, 'checksum' => 'xyz']);
    }

    public function testClear()
    {
        $this->session['auth'] = ['uid' => 'abc', 'context' => 99, 'checksum' => 'xyz'];

        $this->service->clear();
        $this->assertArrayNotHasKey('auth', $this->session->getArrayCopy());
    }
}
