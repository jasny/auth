<?php

declare(strict_types=1);

namespace Jasny\Auth\Tests\Session\Jwt;

use Jasny\Auth\Session\Jwt\CookieMiddleware;
use Jasny\Auth\Session\Jwt\CookieValue;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as ServerRequest;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;

/**
 * @covers \Jasny\Auth\Session\Jwt\CookieMiddleware
 */
class CookieMiddlewareTest extends TestCase
{
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

        $response = $this->createMock(Response::class);
        $response->expects($this->never())->method($this->anything());

        $handler = $this->createMock(RequestHandler::class);
        $handler->expects($this->once())->method('handle')
            ->with($this->identicalTo($cookieRequest))
            ->willReturn($response);

        $result = $this->middleware->process($request, $handler);

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

        $response = $this->createMock(Response::class);
        $response->expects($this->never())->method($this->anything());

        $handler = $this->createMock(RequestHandler::class);
        $handler->expects($this->once())->method('handle')
            ->with($this->identicalTo($cookieRequest))
            ->willReturn($response);

        $result = $this->middleware->process($request, $handler);

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

        $cookieResponse = $this->createMock(Response::class);

        $response = $this->createMock(Response::class);
        $response->expects($this->once())->method('withAddedHeader')
            ->with('Set-Cookie', 'jwt=..TOKEN..; Expires=Wed, 01 Jan 2020 01:00:00 GMT; Domain=example.com; HttpOnly')
            ->willReturn($cookieResponse);

        $handler = $this->createMock(RequestHandler::class);
        $handler->expects($this->once())->method('handle')
            ->with($this->identicalTo($cookieRequest))
            ->willReturnCallback(function () use (&$cookie, $response) {
                $cookie->set('..TOKEN..', strtotime('2020-01-01T01:00:00+0000'));
                return $response;
            });

        $result = $this->middleware->process($request, $handler);

        $this->assertSame($cookieResponse, $result);
    }
}
