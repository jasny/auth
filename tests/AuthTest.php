<?php

namespace Jasny;

use Jasny\Auth;
use PHPUnit_Framework_TestCase as TestCase;
use PHPUnit_Framework_MockObject_MockObject as MockObject;
use Jasny\TestHelper;

/**
 * @covers Jasny\Auth
 */
class AuthTest extends TestCase
{
    use TestHelper;
    
    /**
     * @var Auth|MockObject 
     */
    protected $auth;
    
    public function setUp()
    {
        $this->auth = $this->getMockForAbstractClass(Auth::class);
    }
    
    
    public function testHashPassword()
    {
        $hash = $this->auth->hashPassword('abc');
        $this->assertTrue(password_verify('abc', $hash));
    }
    
    public function invalidPasswordProvider()
    {
        return [
            [''],
            [array()],
            [123]
        ];
    }
    
    /**
     * @dataProvider invalidPasswordProvider
     * @expectedException \InvalidArgumentException
     */
    public function testHashPasswordWithInvalidArgument($password)
    {
        $this->auth->hashPassword($password);
    }
    
    
    public function testVerifyCredentials()
    {
        $hash = password_hash('abc', PASSWORD_BCRYPT);
        
        $user = $this->createMock(Auth\User::class);
        $user->method('getHashedPassword')->willReturn($hash);
        
        $this->assertTrue($this->auth->verifyCredentials($user, 'abc'));
        
        $this->assertFalse($this->auth->verifyCredentials($user, 'god'));
        $this->assertFalse($this->auth->verifyCredentials($user, ''));
    }
    
    
    public function testUserWithoutSessionUser()
    {
        $user = $this->createMock(Auth\User::class);
        $user->expects($this->never())->method('onLogin');
        
        $this->auth->expects($this->once())->method('getCurrentUserId')->willReturn(123);
        $this->auth->expects($this->once())->method('fetchUserById')->with(123)->willReturn($user);
        
        $this->assertSame($user, $this->auth->user());
    }
    
    public function testUserWithSessionUser()
    {
        $this->assertNull($this->auth->user());
    }
    
    
    /**
     * @return Auth|MockObject
     */
    public function testSetUser()
    {
        $user = $this->createMock(Auth\User::class);
        
        $this->auth->expects($this->once())->method('persistCurrentUser');
        
        $result = $this->auth->setUser($user);
        
        $this->assertSame($user, $result);
        $this->assertSame($user, $this->auth->user());
        
        return $this->auth;
    }
    
    public function testSetUserWithExistingUser()
    {
        $this->auth->expects($this->exactly(2))->method('persistCurrentUser');

        $this->auth->setUser($this->createMock(Auth\User::class));
        
        $user = $this->createMock(Auth\User::class);
        $user->expects($this->once())->method('onLogin');
        
        $result = $this->auth->setUser($user);
        
        $this->assertSame($user, $result);
        $this->assertSame($user, $this->auth->user());
    }
    
    public function testSetUserWithOnLoginFail()
    {
        $this->auth->expects($this->once())->method('persistCurrentUser');

        $oldUser = $this->createMock(Auth\User::class);
        $this->auth->setUser($oldUser);
        
        $user = $this->createMock(Auth\User::class);
        $user->expects($this->once())->method('onLogin')->willReturn(false);
        
        $this->auth->expects($this->never())->method('persistCurrentUser');
        
        $result = $this->auth->setUser($user);
        
        $this->assertNull($result);
        $this->assertSame($oldUser, $this->auth->user());
    }
    
    
    public function testLogin()
    {
        $hash = password_hash('abc', PASSWORD_BCRYPT);
        
        $user = $this->createMock(Auth\User::class);
        $user->method('getHashedPassword')->willReturn($hash);
        $user->expects($this->once())->method('onLogin');
        
        $this->auth->expects($this->once())->method('fetchUserByUsername')->with('john')->willReturn($user);
        $this->auth->expects($this->once())->method('persistCurrentUser');
        
        $result = $this->auth->login('john', 'abc');
        
        $this->assertSame($user, $result);
        $this->assertSame($user, $this->auth->user());
    }
    
    public function testLoginWithIncorrectPassword()
    {
        $hash = password_hash('abc', PASSWORD_BCRYPT);
        
        $user = $this->createMock(Auth\User::class);
        $user->method('getHashedPassword')->willReturn($hash);
        $user->expects($this->never())->method('onLogin');
        
        $this->auth->expects($this->once())->method('fetchUserByUsername')->with('john')->willReturn($user);
        $this->auth->expects($this->never())->method('persistCurrentUser');
        
        $result = $this->auth->login('john', 'god');
        
        $this->assertNull($result);
        $this->assertNull($this->auth->user());
    }
    
    public function testLogout()
    {
        $user = $this->createMock(Auth\User::class);
        $user->expects($this->once())->method('onLogout');
        
        $this->auth->setUser($user);
        
        $this->auth->logout();
        
        $this->assertNull($this->auth->user());
        
        // Logout again shouldn't really do anything
        $this->auth->logout();
    }
    
    
    public function testAsMiddleware()
    {
        $callback = $this->createCallbackMock($this->never());
        $middleware = $this->auth->asMiddleware($callback);
        
        $this->assertInstanceOf(Auth\Middleware::class, $middleware);
        $this->assertAttributeEquals($this->auth, 'auth', $middleware);
        $this->assertAttributeEquals($callback, 'getRequiredRole', $middleware);
    }
}
