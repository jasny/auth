<?php

namespace Jasny\Auth;

use Jasny\Auth;
use Jasny\Authz;
use Jasny\AuthAuthz;
use Jasny\Auth\Middleware;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\StreamInterface;
use PHPUnit_Framework_TestCase as TestCase;
use PHPUnit_Framework_MockObject_MockObject as MockObject;
use PHPUnit_Framework_MockObject_Builder_InvocationMocker as InvocationMocker;
use Jasny\TestHelper;

/**
 * @covers Jasny\Auth\Middleware
 */
class MiddlewareTest extends TestCase
{
    use TestHelper;
    
    /**
     * @var Authz|MockObject
     */
    protected $auth;
    
    /**
     * @var Middleware
     */
    protected $middleware;
    
    public function setUp()
    {
        $this->auth = $this->createMock(AuthAuthz::class);
        
        $this->middleware = new Middleware($this->auth, function(ServerRequestInterface $request) {
            return $request->getAttribute('auth');
        });
    }
    
    /**
     * @expectedException \InvalidArgumentException
     */
    public function testConstructInvalidArgument()
    {
        new Middleware($this->auth, 'foo bar zoo');
    }

    
    public function testInvokeWithoutRequiredUser()
    {
        $this->auth->expects($this->never())->method('user');
        
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getAttribute')->with('auth')->willReturn(false);
        
        $finalResponse = $this->createMock(ResponseInterface::class);
        
        $response = $this->createMock(ResponseInterface::class);
        $response->expects($this->never())->method('withStatus');
        
        $next = $this->createCallbackMock(
            $this->once(),
            function(InvocationMocker $invoke) use ($request, $response, $finalResponse) {
                $invoke->with($this->identicalTo($request), $this->identicalTo($response))->willReturn($finalResponse);
            }
        );
        
        $result = call_user_func($this->middleware, $request, $response, $next);
        
        $this->assertSame($finalResponse, $result);
    }
    
    public function testInvokeWithoutRequiredRole()
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getAttribute')->with('auth')->willReturn(null);
        
        $finalResponse = $this->createMock(ResponseInterface::class);
        
        $response = $this->createMock(ResponseInterface::class);
        $response->expects($this->never())->method('withStatus');
        
        $next = $this->createCallbackMock(
            $this->once(),
            function(InvocationMocker $invoke) use ($request, $response, $finalResponse) {
                $invoke->with($this->identicalTo($request), $this->identicalTo($response))->willReturn($finalResponse);
            }
        );
        
        $result = call_user_func($this->middleware, $request, $response, $next);
        
        $this->assertSame($finalResponse, $result);
    }
    
    public function testInvokeWithRequiredUser()
    {
        $user = $this->createMock(Authz\User::class);
        $this->auth->expects($this->once())->method('user')->willReturn($user);
        
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getAttribute')->with('auth')->willReturn(true);
        
        $finalResponse = $this->createMock(ResponseInterface::class);
        
        $response = $this->createMock(ResponseInterface::class);
        $response->expects($this->never())->method('withStatus');
        
        $next = $this->createCallbackMock(
            $this->once(),
            function(InvocationMocker $invoke) use ($request, $response, $finalResponse) {
                $invoke->with($this->identicalTo($request), $this->identicalTo($response))->willReturn($finalResponse);
            }
        );        
        
        $result = call_user_func($this->middleware, $request, $response, $next);
        
        $this->assertSame($finalResponse, $result);
    }
    
    public function testInvokeWithRequiredRole()
    {
        $this->auth->expects($this->once())->method('is')->with('user')->willReturn(true);
        
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getAttribute')->with('auth')->willReturn('user');
        
        $finalResponse = $this->createMock(ResponseInterface::class);
        
        $response = $this->createMock(ResponseInterface::class);
        $response->expects($this->never())->method('withStatus');
        
        $next = $this->createCallbackMock(
            $this->once(),
            function(InvocationMocker $invoke) use ($request, $response, $finalResponse) {
                $invoke->with($this->identicalTo($request), $this->identicalTo($response))->willReturn($finalResponse);
            }
        );        
        
        $result = call_user_func($this->middleware, $request, $response, $next);
        
        $this->assertSame($finalResponse, $result);
    }
    
    public function testInvokeUnauthorized()
    {
        $this->auth->expects($this->once())->method('user')->willReturn(null);
        $this->auth->expects($this->once())->method('is')->with('user')->willReturn(false);
        
        $this->setPrivateProperty($this->middleware, 'auth', $this->auth);
        
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getAttribute')->with('auth')->willReturn('user');
        $request->expects($this->once())->method('getProtocolVersion')->willReturn('1.1');
        
        $stream = $this->createMock(StreamInterface::class);
        $stream->expects($this->once())->method('write')->with('Access denied');
        
        $forbiddenResponse = $this->createMock(ResponseInterface::class);
        $forbiddenResponse->expects($this->once())->method('getBody')->willReturn($stream);
        
        $response = $this->createMock(ResponseInterface::class);
        $response->expects($this->once())->method('withProtocolVersion')->with('1.1')->willReturnSelf();
        $response->expects($this->once())->method('withStatus')->with(401)->willReturn($forbiddenResponse);
        
        $next = $this->createCallbackMock($this->never());
        
        $result = call_user_func($this->middleware, $request, $response, $next);
        
        $this->assertSame($forbiddenResponse, $result);
    }
    
    public function testInvokeForbidden()
    {
        $user = $this->createMock(Authz\User::class);
        
        $this->auth->expects($this->once())->method('user')->willReturn($user);
        $this->auth->expects($this->once())->method('is')->with('user')->willReturn(false);
        
        $request = $this->createMock(ServerRequestInterface::class);
        $request->expects($this->once())->method('getAttribute')->with('auth')->willReturn('user');
        $request->expects($this->once())->method('getProtocolVersion')->willReturn('1.1');
        
        $stream = $this->createMock(StreamInterface::class);
        $stream->expects($this->once())->method('write')->with('Access denied');
        
        $forbiddenResponse = $this->createMock(ResponseInterface::class);
        $forbiddenResponse->expects($this->once())->method('getBody')->willReturn($stream);
        
        $response = $this->createMock(ResponseInterface::class);
        $response->expects($this->once())->method('withProtocolVersion')->with('1.1')->willReturnSelf();
        $response->expects($this->once())->method('withStatus')->with(403)->willReturn($forbiddenResponse);
        
        $next = $this->createCallbackMock($this->never());
        
        $result = call_user_func($this->middleware, $request, $response, $next);
        
        $this->assertSame($forbiddenResponse, $result);
    }
    
    /**
     * @expectedException \InvalidArgumentException
     */
    public function testInvokeInvalidArgument()
    {
        $request = $this->createMock(ServerRequestInterface::class);
        $response = $this->createMock(ResponseInterface::class);
        
        $result = call_user_func($this->middleware, $request, $response, 'foo bar zoo');
    }
}