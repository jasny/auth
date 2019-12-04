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

    protected const STD_HEX = '8930d6fab596adc131412a8309d5391611047dcf9dad6e106ccbb5b8ee2ae7fb20200101120000002a';

    /** @var User&MockObject */
    protected $user;

    public function setUp(): void
    {
        CarbonImmutable::setTestNow('2019-12-01T00:00:00+00:00');

        $this->user = $this->createConfiguredMock(User::class, ['getAuthId' => 42, 'getAuthChecksum' => 'xyz']);
    }

    public function tearDown(): void
    {
        CarbonImmutable::setTestNow(null);
    }

    public function testGetToken()
    {
        $storage = $this->createMock(Storage::class);
        $storage->expects($this->never())->method($this->anything());

        /** @var Hashids&MockObject $hashids */
        $hashids = $this->createMock(Hashids::class);
        $hashids->expects($this->once())->method('encodeHex')
            ->with(self::STD_HEX)
            ->willReturn('the_token');

        $confirm = (new HashidsConfirmation('secret', fn() => $hashids))
            ->withStorage($storage)
            ->withSubject('test');

        $token = $confirm->getToken($this->user, new \DateTime('2020-01-01T12:00:00+00:00'));

        $this->assertEquals('the_token', $token);
    }


    protected function createService(string $hex, ?User $user = null): HashidsConfirmation
    {
        $storage = $this->createMock(Storage::class);

        if (func_num_args() > 1) {
            $storage->expects($this->once())->method('fetchUserById')
                ->with($user !== null ? $user->getAuthId() : 42)
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

        return (new HashidsConfirmation('secret', fn() => $hashids))
            ->withStorage($storage)
            ->withSubject('test');
    }

    public function testFrom()
    {
        $confirm = $this->createService(self::STD_HEX, $this->user);

        $this->assertSame($this->user, $confirm->from('the_token'));
    }


    public function testFromUserWithStringId()
    {
        $hex = '8bbf6e9d7540db35392c348f3effa2ca5687afc9daff2d68747941c077ac2c4120200101120000017a3031';
        $user = $this->createConfiguredMock(User::class, ['getAuthId' => 'z01', 'getAuthChecksum' => 'xyz']);

        $confirm = $this->createService($hex, $user);

        $this->assertSame($user, $confirm->from('the_token'));
    }

    public function testFromDeletedUser()
    {
        $confirm = $this->createService(self::STD_HEX, null);

        $this->expectExceptionObject(new InvalidTokenException("User '42' doesn't exist"));
        $confirm->from('the_token');
    }
    
    public function testFromInvalidChecksum()
    {
        $hex = hash('sha256', '') . '20200101000000' . '002a';

        $confirm = $this->createService($hex, $this->user);

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

    public function testFromInvalidUid()
    {
        $hex = hash('sha256', '') . '20200101000000' . '992a';

        $confirm = $this->createService($hex);

        $this->expectExceptionObject(new InvalidTokenException("Invalid confirmation token"));
        $confirm->from('the_token');
    }

    public function testFromTokenWithInvalidExpireDate()
    {
        $hex = hash('sha256', '') . '99999999000000' . '002a';

        $confirm = $this->createService($hex);

        $this->expectExceptionObject(new InvalidTokenException("Invalid confirmation token"));
        $confirm->from('the_token');
    }

    public function testFromExpiredToken()
    {
        $hex = 'b087edc903ba55d052e51aa2f8a01bc8e68c9503778eedc941e9932b36dd8d09' . '20191101120000' . '002a';

        $confirm = $this->createService($hex);

        $this->expectExceptionObject(new InvalidTokenException("Token is expired"));
        $confirm->from('the_token');
    }

    public function testCreateHashIdsWithCallback()
    {
        $storage = $this->createMock(Storage::class);
        $storage->expects($this->never())->method('fetchUserById');

        /** @var Hashids&MockObject $hashids */
        $hashids = $this->createMock(Hashids::class);

        $salt = hash('sha256', 'testsecret', true);
        $callback = $this->createCallbackMock($this->once(), [$salt], $hashids);

        $service = (new HashidsConfirmation('secret', $callback))
            ->withStorage($storage)
            ->withSubject('test');

        $result = $service->createHashids();

        $this->assertSame($result, $hashids);
    }


    /**
     * @group hashids
     */
    public function testCreateHashIds()
    {
        $storage = $this->createMock(Storage::class);
        $storage->expects($this->never())->method('fetchUserById');

        $service = (new HashidsConfirmation('secret'))
            ->withStorage($storage)
            ->withSubject('test');

        $hashids = $service->createHashids();
        $this->assertInstanceOf(Hashids::class, $hashids);

        $token = $hashids->encodeHex(self::STD_HEX);

        $expectedToken = '6VoyPg4NxJs9VjqQeKRKCV1VyDvYQ7U2bMMygYVxHJge7wVKoGs0JNe6jNwMS6WMA4AmA';
        $this->assertEquals($expectedToken, $token);
    }


    /**
     * @group hashids
     * @coversNothing
     */
    public function testGetTokenWithRealHashids()
    {
        $storage = $this->createMock(Storage::class);
        $storage->expects($this->never())->method($this->anything());

        $confirm = (new HashidsConfirmation('secret'))
            ->withStorage($storage)
            ->withSubject('test');

        $token = $confirm->getToken($this->user, new \DateTime('2020-01-01T12:00:00+00:00'));

        $expectedToken = '6VoyPg4NxJs9VjqQeKRKCV1VyDvYQ7U2bMMygYVxHJge7wVKoGs0JNe6jNwMS6WMA4AmA';
        $this->assertEquals($expectedToken, $token);
    }

    /**
     * @group hashids
     * @coversNothing
     */
    public function testFromWithRealHashids()
    {
        $storage = $this->createMock(Storage::class);
        $storage->expects($this->once())->method('fetchUserById')
            ->with(42)
            ->willReturn($this->user);

        $confirm = (new HashidsConfirmation('secret'))
            ->withStorage($storage)
            ->withSubject('test');

        $user = $confirm->from('6VoyPg4NxJs9VjqQeKRKCV1VyDvYQ7U2bMMygYVxHJge7wVKoGs0JNe6jNwMS6WMA4AmA');

        $this->assertSame($this->user, $user);
    }

    /**
     * @group hashids
     * @coversNothing
     */
    public function testFromOtherSubjectWithRealHashids()
    {
        $storage = $this->createMock(Storage::class);
        $storage->expects($this->never())->method('fetchUserById');

        $confirm = (new HashidsConfirmation('secret'))
            ->withStorage($storage)
            ->withSubject('foo-bar');

        $this->expectException(InvalidTokenException::class);

        $confirm->from('6VoyPg4NxJs9VjqQeKRKCV1VyDvYQ7U2bMMygYVxHJge7wVKoGs0JNe6jNwMS6WMA4AmA');
    }
}
