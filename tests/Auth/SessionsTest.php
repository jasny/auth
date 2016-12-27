<?php

namespace Jasny\Auth;

use Jasny\Auth;
use PHPUnit_Framework_TestCase as TestCase;
use PHPUnit_Framework_MockObject_MockObject as MockObject;
use Jasny\TestHelper;

/**
 * @covers Jasny\Auth\Sessions
 */
class SessionsAuth extends TestCase
{
    use TestHelper;
    
    /**
     * @var Auth\Sessions|MockObject 
     */
    protected $auth;
    
    /**
     * @var string
     */
    protected $sessionModule;

    protected function mockSessionHandling()
    {
        // Mock sessions
        session_cache_limiter('');
        ini_set('session.use_cookies', 0);
        ini_set('session.use_only_cookies', 0);
        
        $this->sessionModule = session_module_name();
        session_set_save_handler($this->createMock(\SessionHandlerInterface::class));
        
        session_start();
    }
    
    protected function restoreSessionHandling()
    {
        session_abort();
        session_module_name($this->sessionModule);
    }
    
    public function setUp()
    {
        $this->auth = $this->getMockForTrait(Auth\Sessions::class);
        $this->mockSessionHandling();
    }
    
    public function tearDown()
    {
        $this->restoreSessionHandling();
    }
    
    
    public function testGetCurrentUserIdWithUser()
    {
        $_SESSION['auth_uid'] = 123;
        
        $id = $this->callPrivateMethod($this->auth, 'getCurrentUserId');
        $this->assertEquals(123, $id);
    }
    
    public function testGetCurrentUserIdWithoutUser()
    {
        $id = $this->callPrivateMethod($this->auth, 'getCurrentUserId');
        $this->assertNull($id);
    }
    
    
    public function testPersistCurrentUserWithUser()
    {
        $_SESSION['foo'] = 'bar';
        
        $user = $this->createMock(Auth\User::class);
        $user->method('getId')->willReturn(123);
        
        $this->auth->expects($this->once())->method('user')->willReturn($user);
        
        $this->callPrivateMethod($this->auth, 'persistCurrentUser');
        
        $this->assertEquals(['foo' => 'bar', 'auth_uid' => 123], $_SESSION);
    }
    
    public function testPersistCurrentUserWithoutUser()
    {
        $_SESSION['auth_uid'] = 123;
        $_SESSION['foo'] = 'bar';
        
        $this->auth->expects($this->once())->method('user')->willReturn(null);
        
        $this->callPrivateMethod($this->auth, 'persistCurrentUser');
        
        $this->assertEquals(['foo' => 'bar'], $_SESSION);
    }
}
