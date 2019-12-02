<?php

namespace Jasny\Auth\Tests;

use Jasny\Auth\AuthzInterface as Authz;
use Jasny\Auth\AuthzMiddleware;
use Jasny\Auth\UserInterface as User;
use Jasny\PHPUnit\CallbackMockTrait;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface as ServerRequest;
use Psr\Http\Message\ResponseFactoryInterface as ResponseFactory;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\StreamInterface as Stream;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;

/**
 * @covers \Jasny\Auth\AuthzMiddleware
 */
class AuthzMiddlewareTest extends TestCase
{
    /** @var Authz&MockObject */
    protected $authz;
    /** @var ResponseFactory&MockObject */
    protected $responseFactory;

    protected AuthzMiddleware $middleware;

    public function setUp(): void
    {
        $this->authz = $this->createMock(Authz::class);
        $this->responseFactory = $this->createMock(ResponseFactory::class);

        $this->middleware = new AuthzMiddleware(
            $this->authz,
            fn(ServerRequest $request) => $request->getAttribute('auth'),
            $this->responseFactory,
        );
    }

    public function testNoRequirements()
    {
        $this->authz->expects($this->never())->method('user');

        $this->responseFactory->expects($this->never())->method('createResponse');

        $request = $this->createMock(ServerRequest::class);
        $request->expects($this->once())->method('getAttribute')->with('auth')->willReturn(null);

        $response = $this->createMock(Response::class);
        $response->expects($this->never())->method($this->anything());

        $handler = $this->createMock(RequestHandler::class);
        $handler->expects($this->once())->method('handle')
            ->with($this->identicalTo($request))
            ->willReturn($response);

        $result = $this->middleware->process($request, $handler);
        
        $this->assertSame($response, $result);
    }

    public function testRequireUser()
    {
        $user = $this->createMock(User::class);
        $this->authz->expects($this->atLeastOnce())->method('user')->willReturn($user);

        $this->responseFactory->expects($this->never())->method('createResponse');

        $request = $this->createMock(ServerRequest::class);
        $request->expects($this->once())->method('getAttribute')->with('auth')->willReturn(true);

        $response = $this->createMock(Response::class);
        $response->expects($this->never())->method($this->anything());

        $handler = $this->createMock(RequestHandler::class);
        $handler->expects($this->once())->method('handle')
            ->with($this->identicalTo($request))
            ->willReturn($response);

        $result = $this->middleware->process($request, $handler);

        $this->assertSame($response, $result);
    }

    public function testRequireNoUser()
    {
        $this->authz->expects($this->atLeastOnce())->method('user')->willReturn(null);

        $this->responseFactory->expects($this->never())->method('createResponse');

        $request = $this->createMock(ServerRequest::class);
        $request->expects($this->once())->method('getAttribute')->with('auth')->willReturn(false);

        $response = $this->createMock(Response::class);
        $response->expects($this->never())->method($this->anything());

        $handler = $this->createMock(RequestHandler::class);
        $handler->expects($this->once())->method('handle')
            ->with($this->identicalTo($request))
            ->willReturn($response);

        $result = $this->middleware->process($request, $handler);

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

        $this->responseFactory->expects($this->once())->method('createResponse')
            ->with(401)
            ->willReturn($forbidden);

        $handler = $this->createMock(RequestHandler::class);
        $handler->expects($this->never())->method('handle');

        $result = $this->middleware->process($request, $handler);

        $this->assertSame($forbidden, $result);
    }

    public function testAccessGranted()
    {
        $this->authz->expects($this->once())->method('is')->with('foo')->willReturn(true);

        $this->responseFactory->expects($this->never())->method('createResponse');

        $request = $this->createMock(ServerRequest::class);
        $request->expects($this->once())->method('getAttribute')->with('auth')->willReturn('foo');

        $response = $this->createMock(Response::class);
        $response->expects($this->never())->method($this->anything());

        $handler = $this->createMock(RequestHandler::class);
        $handler->expects($this->once())->method('handle')
            ->with($this->identicalTo($request))
            ->willReturn($response);

        $result = $this->middleware->process($request, $handler);

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

        $this->responseFactory->expects($this->once())->method('createResponse')
            ->with(403)
            ->willReturn($forbidden);

        $handler = $this->createMock(RequestHandler::class);
        $handler->expects($this->never())->method('handle');

        $result = $this->middleware->process($request, $handler);

        $this->assertSame($forbidden, $result);
    }


    public function testMissingResponseFactory()
    {
        $this->middleware = new AuthzMiddleware(
            $this->authz,
            fn(ServerRequest $request) => $request->getAttribute('auth'),
        );

        $this->authz->expects($this->atLeastOnce())->method('user')->willReturn(null);

        $request = $this->createMock(ServerRequest::class);
        $request->expects($this->once())->method('getAttribute')->with('auth')->willReturn(true);

        $handler = $this->createMock(RequestHandler::class);
        $handler->expects($this->never())->method('handle');

        $this->expectException(\LogicException::class);

        $this->middleware->process($request, $handler);
    }
}