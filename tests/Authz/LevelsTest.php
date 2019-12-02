<?php

namespace Jasny\Auth\Tests\Authz;

use Jasny\Auth\ContextInterface as Context;
use Jasny\Auth\UserInterface as User;
use Jasny\Auth\Authz\Levels;
use Jasny\PHPUnit\ExpectWarningTrait;
use PHPStan\Testing\TestCase;
use PHPUnit\Framework\MockObject\MockObject;

/**
 * @covers \Jasny\Auth\Authz\Levels
 * @covers \Jasny\Auth\Authz\StateTrait
 */
class LevelsTest extends TestCase
{
    use ExpectWarningTrait;
    
    /**
     * @var Levels&MockObject
     */
    protected $authz;
    
    public function setUp(): void
    {
        $this->authz = new Levels([
           'user' => 1,
           'mod' => 10,
           'admin' => 100
        ]);
    }

    public function testGetAvailableRoles()
    {
        $this->assertEquals(['user', 'mod', 'admin'], $this->authz->getAvailableRoles());
    }


    public function testUser()
    {
        $this->assertNull($this->authz->user());

        $user = $this->createMock(User::class);
        $userAuthz = $this->authz->forUser($user);

        $this->assertNotSame($this->authz, $userAuthz);
        $this->assertNull($this->authz->user());
        $this->assertSame($user, $userAuthz->user());
    }

    public function testContext()
    {
        $this->assertNull($this->authz->context());

        $context = $this->createMock(Context::class);
        $contextAuthz = $this->authz->inContextOf($context);

        $this->assertNotSame($this->authz, $contextAuthz);
        $this->assertNull($this->authz->context());
        $this->assertSame($context, $contextAuthz->context());
    }

    
    public function testIsWithoutUser()
    {
        $this->assertFalse($this->authz->is('user'));
    }
    
    public function roleProvider()
    {
        return [
            ['user', ['user' => true, 'mod' => false, 'admin' => false]],
            ['mod', ['user' => true, 'mod' => true, 'admin' => false]],
            ['admin', ['user' => true, 'mod' => true, 'admin' => true]],

            [1, ['user' => true, 'mod' => false, 'admin' => false]],
            [10, ['user' => true, 'mod' => true, 'admin' => false]],
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

        $this->authz = $this->authz->forUser($user);

        $this->assertSame($expect['user'], $this->authz->is('user'));
        $this->assertSame($expect['mod'], $this->authz->is('mod'));
        $this->assertSame($expect['admin'], $this->authz->is('admin'));
    }
    
    public function testIsWithUnknownRole()
    {
        $this->expectWarningMessage("Unknown authz role 'foo'");
        $this->assertFalse($this->authz->is('foo'));
    }

    public function testIsWithUnknownUserRole()
    {
        $user = $this->createConfiguredMock(User::class, ['getRole' => 'foo', 'getId' => 42]);
        $this->authz = $this->authz->forUser($user);

        $this->expectException(\DomainException::class);
        $this->expectExceptionMessage("Authorization level 'foo' isn't defined (uid:42)");
        $this->authz->is('user');
    }

    public function testIsWithInvalidRole()
    {
        $user = $this->createMock(User::class);
        $user->expects($this->any())->method('getRole')->willReturn(['user', 'mod']);

        $this->authz = $this->authz->forUser($user);

        $this->expectException(\UnexpectedValueException::class);
        $this->authz->is('user');
    }
}
