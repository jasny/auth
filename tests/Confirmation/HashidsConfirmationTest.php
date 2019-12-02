<?php

namespace Jasny\Auth\Tests\Confirmation;

use Carbon\CarbonImmutable;
use Hashids\Hashids;
use Jasny\Auth\Confirmation\HashidsConfirmation;
use Jasny\Auth\Confirmation\InvalidTokenException;
use Jasny\Auth\StorageInterface as Storage;
use Jasny\Auth\UserInterface as User;
use Jasny\PHPUnit\CallbackMockTrait;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\MockObject\MockObject;

/**
 * @covers \Jasny\Auth\Confirmation\HashidsConfirmation
 */
class HashidsConfirmationTest extends TestCase
{
    use CallbackMockTrait;

    public function setUp(): void
    {
        CarbonImmutable::setTestNow('2019-12-01T00:00:00+00:00');
    }

    public function tearDown(): void
    {
        CarbonImmutable::setTestNow(null);
    }

    public function testGetToken()
    {
        $hex = join("\n", ["4bd7e1a6bef36da2f5f500a4", "20200101000000+0000", "42"]);

        $user = $this->createConfiguredMock(User::class, ['getId' => 42, 'getAuthChecksum' => 'xyz']);

        $storage = $this->createMock(Storage::class);
        $storage->expects($this->never())->method($this->anything());

        /** @var Hashids&MockObject $hashids */
        $hashids = $this->createMock(Hashids::class);
        $hashids->expects($this->once())->method('encodeHex')
            ->with($hex)
            ->willReturn('the_token');

        $confirm = (new HashidsConfirmation(fn() => $hashids))
            ->withStorage($storage)
            ->withSubject('test');

        $token = $confirm->getToken($user, new \DateTime('2020-01-01T00:00:00+00:00'));

        $this->assertEquals('the_token', $token);
    }


    protected function createService(string $hex, ?User $user = null): HashidsConfirmation
    {
        $storage = $this->createMock(Storage::class);

        if (func_num_args() > 1) {
            $storage->expects($this->once())->method('fetchUserById')
                ->with('42')
                ->willReturn($user);
        } else {
            $storage->expects($this->never())->method('fetchUserById');
        }

        /** @var Hashids&MockObject $hashids */
        $hashids = $this->createMock(Hashids::class);
        $hashids->expects($this->never())->method('encodeHex');
        $hashids->expects($this->once())->method('decodeHex')
            ->with('the_token')
            ->willReturn($hex);

        return (new HashidsConfirmation(fn() => $hashids))
            ->withStorage($storage)
            ->withSubject('test');
    }

    public function testFrom()
    {
        $hex = join("\n", ["4bd7e1a6bef36da2f5f500a4", "20200101000000+0000", "42"]);
        $user = $this->createConfiguredMock(User::class, ['getId' => 42, 'getAuthChecksum' => 'xyz']);

        $confirm = $this->createService($hex, $user);

        $this->assertSame($user, $confirm->from('the_token'));
    }
    
    public function testFromDeletedUser()
    {
        $hex = join("\n", ["4bd7e1a6bef36da2f5f500a4", "20200101000000+0000", "42"]);

        $confirm = $this->createService($hex, null);

        $this->expectExceptionObject(new InvalidTokenException("User '42' doesn't exist"));
        $confirm->from('the_token');
    }
    
    public function testFromInvalidChecksum()
    {
        $hex = join("\n", ["000000000000000000000000", "20200101000000+0000", "42"]);
        $user = $this->createConfiguredMock(User::class, ['getId' => 42, 'getAuthChecksum' => 'xyz']);

        $confirm = $this->createService($hex, $user);

        $this->expectExceptionObject(new InvalidTokenException("Checksum doesn't match"));
        $confirm->from('the_token');
    }

    public function testFromInvalidToken()
    {
        $hex = 'nop';

        $confirm = $this->createService($hex);

        $this->expectExceptionObject(new InvalidTokenException("Invalid confirmation token"));
        $confirm->from('the_token');
    }
    
    public function testFromTokenWithInvalidExpireDate()
    {
        $hex = join("\n", ["000000000000000000000000", "99999999000000+0000", "42"]);

        $confirm = $this->createService($hex);

        $this->expectExceptionObject(new InvalidTokenException("Token date is invalid"));
        $confirm->from('the_token');
    }

    public function testFromExpiredToken()
    {
        $hex = join("\n", ["855c7272569981e79368a47e", "20191101000000+0000", "42"]);

        $confirm = $this->createService($hex);

        $this->expectExceptionObject(new InvalidTokenException("Token is expired"));
        $confirm->from('the_token');
    }
}
