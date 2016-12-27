<?php

namespace Jasny\Authz;

use Jasny\Authz;
use Jasny\Authz\User;
use PHPUnit_Framework_TestCase as TestCase;
use PHPUnit_Framework_MockObject_MockObject as MockObject;
use Jasny\TestHelper;

/**
 * @covers Jasny\Authz\ByLevel
 */
class ByLevelTest extends TestCase
{
    use TestHelper;
    
    /**
     * @var Authz\ByLevel|MockObject
     */
    protected $auth;
    
    public function setUp()
    {
        $this->auth = $this->getMockForTrait(Authz\ByLevel::class);
        
        $this->auth->method('getAccessLevels')->willReturn([
           'user' => 1,
           'mod' => 10,
           'admin' => 100
        ]);
    }
    
    public function testGetLevelWithRole()
    {
        $this->assertSame(1, $this->auth->getLevel('user'));
        $this->assertSame(10, $this->auth->getLevel('mod'));
        $this->assertSame(100, $this->auth->getLevel('admin'));
    }
    
    /**
     * @expectedException \DomainException
     */
    public function testGetLevelWithUnknownRole()
    {
        $this->assertSame(1, $this->auth->getLevel('foo'));
    }
    
    /**
     * @expectedException \InvalidArgumentException
     */
    public function testGetLevelWithInvalidValue()
    {
        $this->assertSame(1, $this->auth->getLevel(['foo']));
    }
    
    public function testGetLevelWithLevel()
    {
        $this->assertSame(100, $this->auth->getLevel(100));
        $this->assertSame(100, $this->auth->getLevel('100'));
    }
    
    
    public function testGetRoles()
    {
        $this->assertEquals(['user', 'mod', 'admin'], $this->auth->getRoles());
    }
    
    /**
     * @expectedException \UnexpectedValueException
     */
    public function testGetRolesWithInvalidStructure()
    {
        $this->auth = $this->getMockForTrait(Authz\ByLevel::class);
        $this->auth->method('getAccessLevels')->willReturn('foo bar');
        
        $this->auth->getRoles();
    }
    
    
    public function testIsWithoutUser()
    {
        $this->assertFalse($this->auth->is('user'));
    }
    
    public function roleProvider()
    {
        return [
            ['user', ['user' => true, 'mod' => false, 'admin' => false]],
            ['mod', ['user' => true, 'mod' => true, 'admin' => false]],
            ['admin', ['user' => true, 'mod' => true, 'admin' => true]],
            [50, ['user' => true, 'mod' => true, 'admin' => false]],
            [500, ['user' => true, 'mod' => true, 'admin' => true]]
        ];
    }
    
    /**
     * @dataProvider roleProvider
     * 
     * @param string|array $role
     * @param array        $expect
     */
    public function testIsWithUser($role, array $expect)
    {
        $user = $this->createMock(User::class);
        $user->method('getRole')->willReturn($role);
        
        $this->auth->method('user')->willReturn($user);
        
        $this->assertSame($expect['user'], $this->auth->is('user'));
        $this->assertSame($expect['mod'], $this->auth->is('mod'));
        $this->assertSame($expect['admin'], $this->auth->is('admin'));
    }
    
    public function testIsWithUnknownRole()
    {
        $this->assertFalse(@$this->auth->is('foo'));
        $this->assertLastError(E_USER_NOTICE, "Unknown role 'foo'");
    }
    
    public function testIsWithUnknownUserRole()
    {
        $user = $this->createMock(User::class);
        $user->method('getRole')->willReturn('foo');
        
        $this->auth->method('user')->willReturn($user);
        
        $this->assertFalse(@$this->auth->is('user'));
        $this->assertLastError(E_USER_NOTICE, "Unknown user role 'foo'");
    }
    
    public function testIsWithInvalidRole()
    {
        $user = $this->createMock(User::class);
        $user->method('getRole')->willReturn(['user']);
        
        $this->auth->method('user')->willReturn($user);
        
        $this->assertFalse(@$this->auth->is('user'));
        $this->assertLastError(E_USER_WARNING, "Expected role to be a string, not a array");
    }
}
