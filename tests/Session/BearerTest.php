<?php

declare(strict_types=1);

namespace Jasny\Auth\Tests\Session;

use Jasny\Auth\Session\Bearer;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

/**
 * @covers \Jasny\Auth\Session\Bearer
 */
class BearerTest extends TestCase
{
    protected Bearer $service;

    public function setUp(): void
    {
        $this->service = new Bearer();
    }

    protected function createServiceForRequest(string $header)
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getHeaderLine')
            ->with('Authorization')
            ->willReturn($header);

        return $this->service->forRequest($request);
    }


    public function testGetInfo()
    {
        $service = $this->createServiceForRequest('Bearer foo');
        $this->assertNotSame($this->service, $service);

        $info = $service->getInfo();
        $this->assertEquals(['uid' => 'foo', 'context' => null, 'checksum' => ''], $info);
    }

    public function testGetInfoDefault()
    {
        $service = $this->createServiceForRequest('');
        $this->assertNotSame($this->service, $service);

        $info = $service->getInfo();
        $this->assertEquals(['uid' => null, 'context' => null, 'checksum' => ''], $info);
    }

    public function testGetInfoWithBasicAuth()
    {
        $service = $this->createServiceForRequest('Basic QWxhZGRpbjpPcGVuU2VzYW1l');
        $this->assertNotSame($this->service, $service);

        $info = $service->getInfo();
        $this->assertEquals(['uid' => null, 'context' => null, 'checksum' => ''], $info);
    }

    public function testGetInfoWithoutRequest()
    {
        $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer xyz';
        $service = new Bearer();

        $info = $service->getInfo();
        $this->assertEquals(['uid' => 'xyz', 'context' => null, 'checksum' => ''], $info);
    }


    public function testPersist()
    {
        $this->expectException(\LogicException::class);
        $this->service->persist('foo', null, '');
    }

    public function testClear()
    {
        $this->expectException(\LogicException::class);
        $this->service->clear();
    }
}
