<?php

declare(strict_types=1);

namespace Jasny\Auth\Tests\Session\Jwt;

use Jasny\Auth\Session\Jwt\CookieMiddleware;
use Jasny\Auth\Session\Jwt\CookieValue;
use Jasny\PHPUnit\CallbackMockTrait;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as ServerRequest;

/**
 * @covers \Jasny\Auth\Session\Jwt\CookieMiddleware
 */
class CookieMiddlewareDoublePassTest extends TestCase
{
    use CallbackMockTrait;

    protected CookieMiddleware $middleware;

    public function setUp(): void
    {
        $this->middleware = new CookieMiddleware('jwt', ['domain' => 'example.com']);
    }

    public function testNoJwt()
    {
        $cookieRequest = $this->createMock(ServerRequest::class);

        $request = $this->createMock(ServerRequest::class);
        $request->expects($this->once())->method('getCookieParams')->willReturn([]);
        $request->expects($this->once())->method('withAttribute')
            ->with('jwt_cookie', $this->callback(function($cookie) {
                $this->assertInstanceOf(CookieValue::class, $cookie);
                $this->assertNull($cookie->get());
                return true;
            }))
            ->willReturn($cookieRequest);

        $initialResp = $this->createMock(Response::class);
        $initialResp->expects($this->never())->method($this->anything());

        $response = $this->createMock(Response::class);
        $response->expects($this->never())->method($this->anything());

        $next = $this->createCallbackMock(
            $this->once(),
            function ($invoke) use ($cookieRequest, $initialResp, $response) {
                return $invoke
                    ->with($this->identicalTo($cookieRequest), $this->identicalTo($initialResp))
                    ->willReturn($response);
            }
        );

        $doublePass = $this->middleware->asDoublePass();
        $result = $doublePass($request, $initialResp, $next);

        $this->assertSame($response, $result);
    }

    public function testWithJwtCookie()
    {
        $cookieRequest = $this->createMock(ServerRequest::class);

        $request = $this->createMock(ServerRequest::class);
        $request->expects($this->once())->method('getCookieParams')
            ->willReturn(['jwt' => '..TOKEN..']);
        $request->expects($this->once())->method('withAttribute')
            ->with('jwt_cookie', $this->callback(function($cookie) {
                $this->assertInstanceOf(CookieValue::class, $cookie);
                $this->assertEquals('..TOKEN..', $cookie->get());
                return true;
            }))
            ->willReturn($cookieRequest);

        $initialResp = $this->createMock(Response::class);
        $initialResp->expects($this->never())->method($this->anything());

        $response = $this->createMock(Response::class);
        $response->expects($this->never())->method($this->anything());

        $next = $this->createCallbackMock(
            $this->once(),
            function ($invoke) use ($cookieRequest, $initialResp, $response) {
                return $invoke
                    ->with($this->identicalTo($cookieRequest), $this->identicalTo($initialResp))
                    ->willReturn($response);
            }
        );

        $doublePass = $this->middleware->asDoublePass();
        $result = $doublePass($request, $initialResp, $next);

        $this->assertSame($response, $result);
    }

    public function testSetJwtCookie()
    {
        /** @var CookieValue|null $cookie */
        $cookie = null;

        $cookieRequest = $this->createMock(ServerRequest::class);

        $request = $this->createMock(ServerRequest::class);
        $request->expects($this->once())->method('getCookieParams')->willReturn([]);
        $request->expects($this->once())->method('withAttribute')
            ->with('jwt_cookie', $this->callback(function($arg) use (&$cookie) {
                $cookie = $arg;
                $this->assertInstanceOf(CookieValue::class, $cookie);
                return true;
            }))
            ->willReturn($cookieRequest);

        $initialResp = $this->createMock(Response::class);
        $initialResp->expects($this->never())->method($this->anything());

        $cookieResponse = $this->createMock(Response::class);

        $response = $this->createMock(Response::class);
        $response->expects($this->once())->method('withAddedHeader')
            ->with('Set-Cookie', 'jwt=..TOKEN..; Expires=Wed, 01 Jan 2020 01:00:00 GMT; Domain=example.com; HttpOnly')
            ->willReturn($cookieResponse);

        $next = $this->createCallbackMock(
            $this->once(),
            function ($invoke) use ($cookieRequest, $initialResp, $response, &$cookie) {
                return $invoke
                    ->with($this->identicalTo($cookieRequest), $this->identicalTo($initialResp))
                    ->willReturnCallback(function () use (&$cookie, $response) {
                        $cookie->set('..TOKEN..', strtotime('2020-01-01T01:00:00+0000'));
                        return $response;
                    });
            }
        );

        $doublePass = $this->middleware->asDoublePass();
        $result = $doublePass($request, $initialResp, $next);

        $this->assertSame($cookieResponse, $result);
    }
}
