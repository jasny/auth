<?php

namespace Jasny\Auth\Tests\Session;

use Jasny\Auth\Session\SessionObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

/**
 * @covers \Jasny\Auth\Session\SessionObject
 */
class SessionObjectTest extends TestCase
{
    protected \ArrayObject $session;
    protected SessionObject $service;

    public function setUp(): void
    {
        $this->session = new \ArrayObject();
        $this->service = new SessionObject($this->session);
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


    protected function createServiceForRequest(\ArrayObject $requestSession)
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getAttribute')
            ->with('session')
            ->willReturn($requestSession);

        return $this->service->forRequest($request);
    }

    public function testGetInfoForRequest()
    {
        $data = ['uid' => 'abc', 'context' => 99, 'checksum' => 'xyz'];

        $requestSession = new \ArrayObject(['auth' => $data + ['other' => 'q']]);
        $service = $this->createServiceForRequest($requestSession);

        $this->assertNotSame($this->service, $service);

        $info = $service->getInfo();
        $this->assertEquals($data, $info);
    }

    public function testPersistForRequest()
    {
        $requestSession = new \ArrayObject(['uid' => 'abc', 'context' => 99, 'checksum' => 'xyz']);
        $service = $this->createServiceForRequest($requestSession);

        $service->persist('abc', 99, 'xyz');

        $this->assertArrayHasKey('auth', $requestSession->getArrayCopy());
        $this->assertEquals($requestSession['auth'], ['uid' => 'abc', 'context' => 99, 'checksum' => 'xyz']);
    }

    public function testClearForRequest()
    {
        $requestSession = new \ArrayObject(['uid' => 'abc', 'context' => 99, 'checksum' => 'xyz']);
        $service = $this->createServiceForRequest($requestSession);

        $service->clear();
        $this->assertArrayNotHasKey('auth', $requestSession->getArrayCopy());
    }


    public function testForRequestWithoutSession()
    {
        $data = ['uid' => 'abc', 'context' => 99, 'checksum' => 'xyz'];
        $this->session['auth'] = $data + ['other' => 'q'];

        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getAttribute')
            ->with('session')
            ->willReturn(null);

        $service = $this->service->forRequest($request);
        $this->assertSame($this->service, $service);

        $info = $service->getInfo();
        $this->assertEquals($data, $info);
    }
}
