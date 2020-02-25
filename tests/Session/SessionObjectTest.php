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
        $data = [
            'user' => 'abc',
            'context' => 99,
            'checksum' => 'xyz',
            'timestamp' => strtotime('2020-01-01T00:00:00+00:00')
        ];
        $this->session['auth'] = $data + ['other' => 'q'];

        $expected = $data;
        $expected['timestamp'] = new \DateTimeImmutable('2020-01-01T00:00:00+00:00');

        $info = $this->service->getInfo();
        $this->assertEquals($expected, $info);
    }

    public function testGetInfoWithoutTimestamp()
    {
        $data = ['user' => 'abc', 'context' => 99, 'checksum' => 'xyz'];
        $this->session['auth'] = $data + ['other' => 'q'];

        $info = $this->service->getInfo();
        $this->assertEquals($data + ['timestamp' => null], $info);
    }

    public function testGetInfoDefaults()
    {
        $info = $this->service->getInfo();
        $this->assertEquals(['user' => null, 'context' => null, 'checksum' => null, 'timestamp' => null], $info);
    }

    public function testPersist()
    {
        $timestamp = new \DateTimeImmutable('2020-01-01T00:00:00+00:00');

        $this->service->persist('abc', 99, 'xyz', $timestamp);

        $expected = [
            'user' => 'abc',
            'context' => 99,
            'checksum' => 'xyz',
            'timestamp' => strtotime('2020-01-01T00:00:00+00:00')
        ];

        $this->assertArrayHasKey('auth', $this->session->getArrayCopy());
        $this->assertEquals($expected, $this->session['auth']);
    }

    public function testClear()
    {
        $this->session['auth'] = ['user' => 'abc', 'context' => 99, 'checksum' => 'xyz', 'timestamp' => null];

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
        $data = ['user' => 'abc', 'context' => 99, 'checksum' => 'xyz', 'timestamp' => null];

        $requestSession = new \ArrayObject(['auth' => $data + ['other' => 'q']]);
        $service = $this->createServiceForRequest($requestSession);

        $this->assertNotSame($this->service, $service);

        $info = $service->getInfo();
        $this->assertEquals($data, $info);
    }

    public function testPersistForRequest()
    {
        $requestSession = new \ArrayObject(['user' => 'abc', 'context' => 99, 'checksum' => 'xyz', 'timestamp' => null]);
        $service = $this->createServiceForRequest($requestSession);

        $service->persist('abc', 99, 'xyz', null);

        $expected = ['user' => 'abc', 'context' => 99, 'checksum' => 'xyz', 'timestamp' => null];

        $this->assertArrayHasKey('auth', $requestSession->getArrayCopy());
        $this->assertEquals($expected, $requestSession['auth']);
    }

    public function testClearForRequest()
    {
        $requestSession = new \ArrayObject(['user' => 'abc', 'context' => 99, 'checksum' => 'xyz', 'timestamp' => null]);
        $service = $this->createServiceForRequest($requestSession);

        $service->clear();
        $this->assertArrayNotHasKey('auth', $requestSession->getArrayCopy());
    }


    public function testForRequestWithoutSession()
    {
        $data = ['user' => 'abc', 'context' => 99, 'checksum' => 'xyz', 'timestamp' => null];
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
