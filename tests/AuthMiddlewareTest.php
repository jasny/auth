<?php

namespace Jasny\Auth\Tests;

use Jasny\Auth\Auth;
use Jasny\Auth\AuthzInterface as Authz;
use Jasny\Auth\AuthMiddleware;
use Jasny\Auth\Session\SessionInterface;
use Jasny\PHPUnit\CallbackMockTrait;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface as ServerRequest;
use Psr\Http\Message\ResponseFactoryInterface as ResponseFactory;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\StreamInterface as Stream;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;

/**
 * @covers \Jasny\Auth\AuthMiddleware
 */
class AuthMiddlewareTest extends TestCase
{
    use CallbackMockTrait;

    /** @var Authz&MockObject */
    protected $authz;
    /** @var ResponseFactory&MockObject */
    protected $responseFactory;

    protected AuthMiddleware $middleware;

    public function setUp(): void
    {
        $this->authz = $this->createMock(Authz::class);
        $this->responseFactory = $this->createMock(ResponseFactory::class);

        $this->middleware = new AuthMiddleware(
            $this->authz,
            fn(ServerRequest $request) => $request->getAttribute('auth'),
            $this->responseFactory,
        );
    }

    public function testNoRequirements()
    {
        $this->authz->expects($this->never())->method($this->anything());

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
        $this->authz->expects($this->atLeastOnce())->method('isLoggedIn')->willReturn(true);

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
        $this->authz->expects($this->atLeastOnce())->method('isLoggedIn')->willReturn(false);

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
        $this->authz->expects($this->atLeastOnce())->method('isLoggedIn')->willReturn(false);

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
        $this->authz->expects($this->atLeastOnce())->method('isLoggedIn')->willReturn(true);
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
        $middleware = new AuthMiddleware(
            $this->authz,
            fn(ServerRequest $request) => $request->getAttribute('auth'),
        );

        $this->authz->expects($this->atLeastOnce())->method('isLoggedIn')->willReturn(false);

        $request = $this->createMock(ServerRequest::class);
        $request->expects($this->once())->method('getAttribute')->with('auth')->willReturn(true);

        $handler = $this->createMock(RequestHandler::class);
        $handler->expects($this->never())->method('handle');

        $this->expectException(\LogicException::class);

        $middleware->process($request, $handler);
    }


    public function testInitialize()
    {
        $auth = $this->createMock(Auth::class);
        $auth->expects($this->once())->method('initialize');

        $response = $this->createMock(Response::class);

        $request = $this->createMock(ServerRequest::class);
        $request->expects($this->once())->method('getAttribute')->with('auth')->willReturn(null);

        $middleware = new AuthMiddleware(
            $auth,
            fn(ServerRequest $request) => $request->getAttribute('auth'),
            $this->responseFactory
        );

        $handler = $this->createMock(RequestHandler::class);
        $handler->expects($this->once())->method('handle')
            ->with($this->identicalTo($request))
            ->willReturn($response);

        $middleware->process($request, $handler);
    }

    public function testInitializeWithSession()
    {
        $session = $this->createMock(SessionInterface::class);

        $auth = $this->createMock(Auth::class);
        $auth->expects($this->once())->method('initialize')
            ->with($this->identicalTo($session));

        $response = $this->createMock(Response::class);

        $request = $this->createMock(ServerRequest::class);
        $request->expects($this->once())->method('getAttribute')->with('auth')->willReturn(null);

        $sessionCallback = $this->createCallbackMock($this->once(), [$this->identicalTo($request)], $session);

        $middleware = (new AuthMiddleware(
            $auth,
            fn(ServerRequest $request) => $request->getAttribute('auth'),
            $this->responseFactory
        ))->withSession($sessionCallback);

        $handler = $this->createMock(RequestHandler::class);
        $handler->expects($this->once())->method('handle')
            ->with($this->identicalTo($request))
            ->willReturn($response);

        $middleware->process($request, $handler);
    }

    public function testInitializeWithBadSessionCallback()
    {
        $auth = $this->createMock(Auth::class);
        $auth->expects($this->never())->method('initialize');

        $request = $this->createMock(ServerRequest::class);

        $sessionCallback = $this->createCallbackMock($this->once(), [$this->identicalTo($request)], 'hello');

        $middleware = (new AuthMiddleware(
            $auth,
            fn(ServerRequest $request) => $request->getAttribute('auth'),
            $this->responseFactory
        ))->withSession($sessionCallback);

        $handler = $this->createMock(RequestHandler::class);
        $handler->expects($this->never())->method('handle');

        $this->expectException(\UnexpectedValueException::class);

        $middleware->process($request, $handler);
    }

    public function testInitializeCantUseSession()
    {
        $request = $this->createMock(ServerRequest::class);

        $auth = $this->createMock(Authz::class);

        $middleware = (new AuthMiddleware(
            $auth,
            fn(ServerRequest $request) => $request->getAttribute('auth'),
            $this->responseFactory
        ))->withSession(fn() => null);

        $handler = $this->createMock(RequestHandler::class);
        $handler->expects($this->never())->method('handle');

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage("Session can't be used for immutable authz service");

        $middleware->process($request, $handler);
    }
}
