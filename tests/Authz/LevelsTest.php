<?php

namespace Jasny\Auth\Tests\Authz;

use Jasny\Auth\AuthException;
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

    public function testNoUser()
    {
        $this->assertFalse($this->authz->isLoggedIn());

        $this->expectException(AuthException::class);
        $this->authz->user();
    }

    public function testUser()
    {
        $user = $this->createConfiguredMock(User::class, ['getAuthRole' => 'user']);
        $userAuthz = $this->authz->forUser($user);

        $this->assertTrue($userAuthz->isLoggedIn());
        $this->assertFalse($this->authz->isLoggedIn());

        $this->assertNotSame($this->authz, $userAuthz);
        $this->assertSame($user, $userAuthz->user());
    }

    public function testWithUnknownUserRole()
    {
        $user = $this->createConfiguredMock(User::class, ['getAuthRole' => 'foo', 'getAuthId' => 42]);

        $this->expectException(\DomainException::class);
        $this->expectExceptionMessage("Authorization level 'foo' isn't defined (uid:42)");

        $this->authz = $this->authz->forUser($user);
    }

    public function testWithInvalidUserRole()
    {
        $user = $this->createMock(User::class);
        $user->expects($this->any())->method('getAuthRole')->willReturn(['user', 'mod']);

        $this->expectException(\UnexpectedValueException::class);

        $this->authz = $this->authz->forUser($user);
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
        $user->method('getAuthRole')->willReturn($role);

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


    public function testRecalc()
    {
        $user = $this->createMock(User::class);
        $user->expects($this->exactly(2))->method('getAuthRole')
            ->willReturnOnConsecutiveCalls('user', 'admin');

        $this->authz = $this->authz->forUser($user);

        $this->assertTrue($this->authz->is('user'));
        $this->assertFalse($this->authz->is('mod'));

        // $user->role = 'admin';
        $updatedAuthz = $this->authz->recalc();

        $this->assertFalse($this->authz->is('mod'));
        $this->assertTrue($updatedAuthz->is('mod')); // admin supersedes dev
    }

    public function testRecalcWithoutAnyChange()
    {
        $user = $this->createMock(User::class);
        $user->expects($this->exactly(2))->method('getAuthRole')
            ->willReturnOnConsecutiveCalls('user', 'user');

        $this->authz = $this->authz->forUser($user);
        $updatedAuthz = $this->authz->recalc();

        $this->assertSame($this->authz, $updatedAuthz);
    }

    public function testRecalcWithoutUser()
    {
        $this->authz = $this->authz->forUser(null);
        $updatedAuthz = $this->authz->recalc();

        $this->assertSame($this->authz, $updatedAuthz);
    }
}
