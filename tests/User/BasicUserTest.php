<?php

declare(strict_types=1);

namespace Jasny\Auth\Tests\User;

use Jasny\Auth\User\BasicUser;
use PHPUnit\Framework\TestCase;

/**
 * @covers \Jasny\Auth\User\BasicUser
 */
class BasicUserTest extends TestCase
{
    public function testFromData()
    {
        $user = BasicUser::fromData([
            'id' => 42,
            'username' => 'john',
            'hashedPassword' => password_hash('open', PASSWORD_BCRYPT),
            'role' => 'admin',
        ]);

        $this->assertInstanceOf(BasicUser::class, $user);

        $this->assertEquals(42, $user->id);
        $this->assertObjectHasAttribute('username', $user);
        $this->assertEquals('john', $user->username);
        $this->assertEquals('admin', $user->role);

        return $user;
    }

    /**
     * @depends testFromData
     */
    public function testGetAuthId(BasicUser $user)
    {
        $this->assertEquals('42', $user->getAuthId());
    }

    /**
     * @depends testFromData
     */
    public function testVerifyPassword(BasicUser $user)
    {
        $this->assertTrue($user->verifyPassword('open'));

        $this->assertFalse($user->verifyPassword('fake'));
        $this->assertFalse($user->verifyPassword(''));
    }

    /**
     * @depends testFromData
     */
    public function testRequiresMfa(BasicUser $user)
    {
        $this->assertFalse($user->requiresMfa());
    }

    public function testGetAuthChecksum()
    {
        $hashedPassword = password_hash('open', PASSWORD_BCRYPT);

        $user = BasicUser::fromData([
            'id' => 42,
            'hashedPassword' => $hashedPassword,
        ]);

        $this->assertEquals(
            hash('sha256', '42' . $hashedPassword),
            $user->getAuthChecksum()
        );
    }

    /**
     * @depends testFromData
     */
    public function testGetAuthRole(BasicUser $user)
    {
        $this->assertEquals('admin', $user->getAuthRole());
    }
}
