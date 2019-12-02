<?php

namespace Jasny\Auth\Tests;

use Jasny\Auth\AuthzInterface as Authz;
use Jasny\Auth\AuthzMiddleware;
use Jasny\Auth\UserInterface as User;
use Jasny\PHPUnit\CallbackMockTrait;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface as ServerRequest;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\StreamInterface as Stream;

/**
 * @covers \Jasny\Auth\AuthzMiddleware
 */
class AuthzMiddlewareDoublePassTest extends TestCase
{
    use CallbackMockTrait;

    /** @var Authz&MockObject */
    protected $authz;

    protected AuthzMiddleware $middleware;

    public function setUp(): void
    {
        $this->authz = $this->createMock(Authz::class);

        $this->middleware = new AuthzMiddleware(
            $this->authz,
            fn(ServerRequest $request) => $request->getAttribute('auth'),
        );
    }

    public function testNoRequirements()
    {
        $this->authz->expects($this->never())->method('user');

        $request = $this->createMock(ServerRequest::class);
        $request->expects($this->once())->method('getAttribute')->with('auth')->willReturn(null);

        $initialResp = $this->createMock(Response::class);

        $response = $this->createMock(Response::class);
        $response->expects($this->never())->method($this->anything());

        $next = $this->createCallbackMock($this->once(), function ($invoke) use ($request, $initialResp, $response) {
            return $invoke
                ->with($this->identicalTo($request), $this->identicalTo($initialResp))
                ->willReturn($response);
        });

        $doublePass = $this->middleware->asDoublePass();
        $result = $doublePass($request, $initialResp, $next);
        
        $this->assertSame($response, $result);
    }

    public function testRequireUser()
    {
        $user = $this->createMock(User::class);
        $this->authz->expects($this->atLeastOnce())->method('user')->willReturn($user);

        $request = $this->createMock(ServerRequest::class);
        $request->expects($this->once())->method('getAttribute')->with('auth')->willReturn(true);

        $initialResp = $this->createMock(Response::class);

        $response = $this->createMock(Response::class);
        $response->expects($this->never())->method($this->anything());

        $next = $this->createCallbackMock($this->once(), function ($invoke) use ($request, $initialResp, $response) {
            return $invoke
                ->with($this->identicalTo($request), $this->identicalTo($initialResp))
                ->willReturn($response);
        });

        $doublePass = $this->middleware->asDoublePass();
        $result = $doublePass($request, $initialResp, $next);

        $this->assertSame($response, $result);
    }

    public function testRequireNoUser()
    {
        $this->authz->expects($this->atLeastOnce())->method('user')->willReturn(null);

        $request = $this->createMock(ServerRequest::class);
        $request->expects($this->once())->method('getAttribute')->with('auth')->willReturn(false);

        $initialResp = $this->createMock(Response::class);

        $response = $this->createMock(Response::class);
        $response->expects($this->never())->method($this->anything());

        $next = $this->createCallbackMock($this->once(), function ($invoke) use ($request, $initialResp, $response) {
            return $invoke
                ->with($this->identicalTo($request), $this->identicalTo($initialResp))
                ->willReturn($response);
        });

        $doublePass = $this->middleware->asDoublePass();
        $result = $doublePass($request, $initialResp, $next);

        $this->assertSame($response, $result);
    }

    public function testLoginRequired()
    {
        $this->authz->expects($this->atLeastOnce())->method('user')->willReturn(null);

        $request = $this->createMock(ServerRequest::class);
        $request->expects($this->once())->method('getAttribute')->with('auth')->willReturn(true);
        $request->expects($this->once())->method('getProtocolVersion')->willReturn('1.1');

        $body = $this->createMock(Stream::class);
        $body->expects($this->once())->method('write')->with('Access denied');

        $forbidden = $this->createMock(Response::class);
        $forbidden->expects($this->once())->method('withProtocolVersion')->with('1.1')->willReturnSelf();
        $forbidden->expects($this->once())->method('getBody')->willReturn($body);

        $initialResp = $this->createMock(Response::class);
        $initialResp->expects($this->once())->method('withStatus')->with(401)->willReturnSelf();
        $initialResp->expects($this->once())->method('getBody')->willReturn($body);
        $initialResp->expects($this->once())->method('withBody')->willReturn($forbidden);

        $next = $this->createCallbackMock($this->never());

        $doublePass = $this->middleware->asDoublePass();
        $result = $doublePass($request, $initialResp, $next);

        $this->assertSame($forbidden, $result);
    }

    public function testAccessGranted()
    {
        $this->authz->expects($this->once())->method('is')->with('foo')->willReturn(true);

        $request = $this->createMock(ServerRequest::class);
        $request->expects($this->once())->method('getAttribute')->with('auth')->willReturn('foo');

        $initialResp = $this->createMock(Response::class);

        $response = $this->createMock(Response::class);
        $response->expects($this->never())->method($this->anything());

        $next = $this->createCallbackMock($this->once(), function ($invoke) use ($request, $initialResp, $response) {
            return $invoke
                ->with($this->identicalTo($request), $this->identicalTo($initialResp))
                ->willReturn($response);
        });

        $doublePass = $this->middleware->asDoublePass();
        $result = $doublePass($request, $initialResp, $next);

        $this->assertSame($response, $result);
    }

    public function testAccessDenied()
    {
        $user = $this->createMock(User::class);

        $this->authz->expects($this->atLeastOnce())->method('user')->willReturn($user);
        $this->authz->expects($this->once())->method('is')->with('foo')->willReturn(false);

        $request = $this->createMock(ServerRequest::class);
        $request->expects($this->once())->method('getAttribute')->with('auth')->willReturn('foo');
        $request->expects($this->once())->method('getProtocolVersion')->willReturn('1.1');

        $body = $this->createMock(Stream::class);
        $body->expects($this->once())->method('write')->with('Access denied');

        $forbidden = $this->createMock(Response::class);
        $forbidden->expects($this->once())->method('withProtocolVersion')->with('1.1')->willReturnSelf();
        $forbidden->expects($this->once())->method('getBody')->willReturn($body);

        $initialResp = $this->createMock(Response::class);
        $initialResp->expects($this->once())->method('withStatus')->with(403)->willReturnSelf();
        $initialResp->expects($this->once())->method('getBody')->willReturn($body);
        $initialResp->expects($this->once())->method('withBody')->willReturn($forbidden);

        $next = $this->createCallbackMock($this->never());

        $doublePass = $this->middleware->asDoublePass();
        $result = $doublePass($request, $initialResp, $next);

        $this->assertSame($forbidden, $result);
    }
}