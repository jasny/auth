<?php

namespace Jasny\Authz;

use Jasny\Authz;
use Jasny\Authz\User;
use PHPUnit_Framework_TestCase as TestCase;
use PHPUnit_Framework_MockObject_MockObject as MockObject;
use Jasny\TestHelper;

/**
 * @covers Jasny\Authz\ByGroup
 */
class ByGroupTest extends TestCase
{
    use TestHelper;
    
    /**
     * @var Authz\ByGroup|MockObject
     */
    protected $auth;
    
    public function setUp()
    {
        $this->auth = $this->getMockForTrait(Authz\ByGroup::class);
        
        $this->auth->method('getGroupStructure')->willReturn([
           'user' => [],
           'client' => ['user'],
           'mod' => ['user'],
           'dev' => ['user'],
           'admin' => ['mod', 'dev']
        ]);
    }
    
    public function testGetRoles()
    {
        $this->assertEquals(['user', 'client', 'mod', 'dev', 'admin'], $this->auth->getRoles());
    }
    
    /**
     * @expectedException \UnexpectedValueException
     */
    public function testGetRolesWithInvalidStructure()
    {
        $this->auth = $this->getMockForTrait(Authz\ByGroup::class);
        $this->auth->method('getGroupStructure')->willReturn('foo bar');
        
        $this->auth->getRoles();
    }
    
    
    public function testIsWithoutUser()
    {
        $this->assertFalse($this->auth->is('user'));
    }
    
    public function roleProvider()
    {
        return [
            ['user', ['user' => true, 'client' => false, 'mod' => false, 'dev' => false, 'admin' => false]],
            ['client', ['user' => true, 'client' => true, 'mod' => false, 'dev' => false, 'admin' => false]],
            ['admin', ['user' => true, 'client' => false, 'mod' => true, 'dev' => true, 'admin' => true]],
            [['mod', 'client'], ['user' => true, 'client' => true, 'mod' => true, 'dev' => false, 'admin' => false]],
            [['user', 'foo'], ['user' => true, 'client' => false, 'mod' => false, 'dev' => false, 'admin' => false]],
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
        $this->assertSame($expect['client'], $this->auth->is('client'));
        $this->assertSame($expect['mod'], $this->auth->is('mod'));
        $this->assertSame($expect['dev'], $this->auth->is('dev'));
        $this->assertSame($expect['admin'], $this->auth->is('admin'));
    }
    
    public function testIsWithUnknownRole()
    {
        $this->assertFalse(@$this->auth->is('foo'));
        $this->assertLastError(E_USER_NOTICE, "Unknown role 'foo'");
    }
}
