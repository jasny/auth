<?php

namespace Jasny\Auth\Tests;

use Jasny\Auth\Auth;
use Jasny\Auth\AuthzInterface as Authz;
use Jasny\Auth\Confirmation\ConfirmationInterface as Confirmation;
use Jasny\Auth\ContextInterface as Context;
use Jasny\Auth\Event;
use Jasny\Auth\LoginException;
use Jasny\Auth\Session\SessionInterface as Session;
use Jasny\Auth\StorageInterface as Storage;
use Jasny\Auth\User\PartiallyLoggedIn;
use Jasny\Auth\UserInterface as User;
use Jasny\PHPUnit\CallbackMockTrait;
use Jasny\PHPUnit\PrivateAccessTrait;
use PHPUnit\Framework\TestCase;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\EventDispatcher\EventDispatcherInterface as EventDispatcher;
use Psr\Log\LoggerInterface;

/**
 * @covers \Jasny\Auth\Auth
 */
class AuthTest extends TestCase
{
    use CallbackMockTrait;
    use PrivateAccessTrait;

    protected Auth $service;

    /** @var Authz&MockObject */
    protected $authz;
    /** @var Session&MockObject */
    protected $session;
    /** @var Storage&MockObject */
    protected $storage;
    /** @var Confirmation&MockObject */
    protected $confirmation;

    /** @var EventDispatcher&MockObject */
    protected $dispatcher;
    /** @var LoggerInterface&MockObject */
    protected $logger;

    public function setUp(): void
    {
        $this->authz = $this->createMock(Authz::class);
        $this->storage = $this->createMock(Storage::class);
        $this->confirmation = $this->createMock(Confirmation::class);
        $this->session = $this->createMock(Session::class);

        $this->dispatcher = $this->createMock(EventDispatcher::class);
        $this->logger = $this->createMock(LoggerInterface::class);

        $this->service = (new Auth($this->authz, $this->storage, $this->confirmation))
            ->withEventDispatcher($this->dispatcher)
            ->withLogger($this->logger);

        if (!in_array('initialize', $this->getGroups(), true)) {
            $this->setPrivateProperty($this->service, 'session', $this->session);
        }
    }


    /**
     * @return Authz&MockObject
     */
    protected function createNewAuthzMock(?User $user, ?Context $context)
    {
        $newAuthz = $this->createMock(Authz::class);
        $loggedIn = $user !== null;

        if (!$loggedIn) {
            $newAuthz->expects($this->never())->method('user');
        } else {
            $newAuthz->expects($this->any())->method('user')->willReturn($user);
        }

        $newAuthz->expects($this->any())->method('isLoggedIn')->willReturn($loggedIn);
        $newAuthz->expects($this->any())->method('isLoggedOut')->willReturn(!$loggedIn);
        $newAuthz->expects($this->any())->method('isPartiallyLoggedIn')->willReturn(false);
        $newAuthz->expects($this->any())->method('context')->willReturn($context);

        return $newAuthz;
    }

    /**
     * @return Authz&MockObject
     */
    protected function expectInitAuthz(?User $user, ?Context $context)
    {
        $newAuthz = $this->createNewAuthzMock($user, $context);

        $this->authz->expects($this->once())->method('forUser')
            ->with($this->identicalTo($user))
            ->willReturnSelf();
        $this->authz->expects($this->once())->method('inContextOf')
            ->with($this->identicalTo($context))
            ->willReturn($newAuthz);

        return $newAuthz;
    }


    /**
     * @return Authz&MockObject
     */
    protected function expectSetAuthzUser(?User $user, ?Context $context = null)
    {
        $newAuthz = $this->createNewAuthzMock($user, $context);

        $this->authz->expects($this->once())->method('forUser')
            ->with($this->identicalTo($user))
            ->willReturn($newAuthz);

        return $newAuthz;
    }

    /**
     * @return Authz&MockObject
     */
    protected function expectSetAuthzContext(?User $user, ?Context $context)
    {
        $newAuthz = $this->createNewAuthzMock($user, $context);

        $this->authz->expects($this->once())->method('inContextOf')
            ->with($this->identicalTo($context))
            ->willReturn($newAuthz);

        return $newAuthz;
    }

    /**
     * @return Authz&MockObject
     */
    protected function expectAuthzWithPartialLogin(User $user)
    {
        $newAuthz = $this->createMock(Authz::class);
        $newAuthz->expects($this->any())->method('isLoggedIn')->willReturn(false);
        $newAuthz->expects($this->any())->method('isLoggedOut')->willReturn(false);
        $newAuthz->expects($this->any())->method('isPartiallyLoggedIn')->willReturn(true);
        $newAuthz->expects($this->any())->method('user')->willReturn(new PartiallyLoggedIn($user));

        $this->authz->expects($this->once())->method('forUser')
            ->with($this->callback(function ($authzUser) use ($user) {
                $this->assertInstanceOf(PartiallyLoggedIn::class, $authzUser);
                $this->assertSame($user, $authzUser->getUser());
                return true;
            }))
            ->willReturn($newAuthz);

        $newAuthz->expects($this->any())->method('inContextOf')->with(null)->willReturnSelf();

        return $newAuthz;
    }

    public function testWithLogger()
    {
        $this->assertSame($this->logger, $this->service->getLogger());

        $newLogger = $this->createMock(LoggerInterface::class);
        $newService = $this->service->withLogger($newLogger);

        $this->assertInstanceOf(Auth::class, $newService);
        $this->assertSame($newLogger, $newService->getLogger());

        $this->assertNotSame($this->logger, $newLogger);
        $this->assertSame($this->logger, $this->service->getLogger());
    }

    /**
     * @group initialize
     */
    public function testInitializeWithoutSession()
    {
        //<editor-fold desc="[prepare mocks]">
        $this->session->expects($this->once())
            ->method('getInfo')
            ->willReturn(['user' => null, 'context' => null, 'checksum' => null, 'timestamp' => null]);

        $this->storage->expects($this->never())->method($this->anything());
        //</editor-fold>

        $newAuthz = $this->expectInitAuthz(null, null);

        $this->assertFalse($this->service->isInitialized());

        $this->service->initialize($this->session);

        $this->assertTrue($this->service->isInitialized());
        $this->assertSame($newAuthz, $this->service->authz());

        return $this->service;
    }

    /**
     * @depends testInitializeWithoutSession
     * @group initialize
     */
    public function testInitializeTwice(Auth $service)
    {
        $this->expectException(\LogicException::class);
        $service->initialize($this->session);
    }

    /**
     * @group initialize
     */
    public function testInitializeWithUser()
    {
        $user = $this->createConfiguredMock(User::class, ['getAuthId' => '42', 'getAuthChecksum' => 'abc']);

        //<editor-fold desc="[prepare mocks]">
        $timestamp = new \DateTimeImmutable('2020-01-01T00:00:00+00:00');

        $this->session->expects($this->once())
            ->method('getInfo')
            ->willReturn(['user' => '42', 'context' => null, 'checksum' => 'abc', 'timestamp' => $timestamp]);

        $this->storage->expects($this->once())->method('fetchUserById')
            ->with('42')
            ->willReturn($user);
        $this->storage->expects($this->never())->method('fetchContext');
        //</editor-fold>

        $newAuthz = $this->expectInitAuthz($user, null);

        $this->service->initialize($this->session);

        $this->assertSame($newAuthz, $this->service->authz());
        $this->assertEquals($timestamp, $this->service->time());
    }

    /**
     * @group initialize
     */
    public function testInitializeWithUserAndContext()
    {
        $user = $this->createConfiguredMock(User::class, ['getAuthId' => '42', 'getAuthChecksum' => 'abc']);
        $context = $this->createConfiguredMock(Context::class, ['getAuthId' => 'foo']);

        //<editor-fold desc="[prepare mocks]">
        $timestamp = new \DateTimeImmutable('2020-01-01T00:00:00+00:00');

        $this->session->expects($this->once())
            ->method('getInfo')
            ->willReturn(['user' => '42', 'context' => 'foo', 'checksum' => 'abc', 'timestamp' => $timestamp]);

        $this->storage->expects($this->once())->method('fetchUserById')
            ->with('42')
            ->willReturn($user);
        $this->storage->expects($this->once())->method('fetchContext')
            ->with('foo')
            ->willReturn($context);
        //</editor-fold>

        $newAuthz = $this->expectInitAuthz($user, $context);

        $this->service->initialize($this->session);

        $this->assertSame($newAuthz, $this->service->authz());
        $this->assertEquals($timestamp, $this->service->time());
    }

    /**
     * @group initialize
     */
    public function testInitializeWithUserAndContextObjects()
    {
        $user = $this->createConfiguredMock(User::class, ['getAuthId' => '42', 'getAuthChecksum' => 'abc']);
        $context = $this->createConfiguredMock(Context::class, ['getAuthId' => 'foo']);

        //<editor-fold desc="[prepare mocks]">
        $this->session->expects($this->once())
            ->method('getInfo')
            ->willReturn(['user' => $user, 'context' => $context, 'checksum' => 'abc', 'timestamp' => null]);

        $this->storage->expects($this->never())->method('fetchUserById');
        $this->storage->expects($this->never())->method('fetchContext');
        //</editor-fold>

        $newAuthz = $this->expectInitAuthz($user, $context);

        $this->service->initialize($this->session);

        $this->assertSame($newAuthz, $this->service->authz());
    }

    /**
     * @group initialize
     */
    public function testInitializeWithInvalidAuthChecksum()
    {
        $user = $this->createConfiguredMock(User::class, ['getAuthId' => '42', 'getAuthChecksum' => 'xyz']);

        //<editor-fold desc="[prepare mocks]">
        $this->session->expects($this->once())
            ->method('getInfo')
            ->willReturn(['user' => '42', 'context' => null, 'checksum' => 'abc', 'timestamp' => null]);

        $this->storage->expects($this->once())->method('fetchUserById')
            ->with('42')
            ->willReturn($user);
        $this->storage->expects($this->never())->method('fetchContext');

        $this->logger->expects($this->once())->method('notice')
            ->with("Ignoring auth info from session: invalid checksum", ['user' => '42']);
        //</editor-fold>

        $newAuthz = $this->expectInitAuthz(null, null);

        $this->service->initialize($this->session);

        $this->assertSame($newAuthz, $this->service->authz());
    }

    /**
     * @group initialize
     */
    public function testInitializeWithPartialLogin()
    {
        $user = $this->createConfiguredMock(User::class, ['getAuthId' => '42', 'getAuthChecksum' => 'abc']);

        //<editor-fold desc="[prepare mocks]">
        $timestamp = new \DateTimeImmutable('2020-01-01T00:00:00+00:00');

        $this->session->expects($this->once())
            ->method('getInfo')
            ->willReturn(['user' => '#partial:42', 'context' => null, 'checksum' => 'abc', 'timestamp' => $timestamp]);

        $this->storage->expects($this->once())->method('fetchUserById')
            ->with('42')
            ->willReturn($user);
        $this->storage->expects($this->never())->method('fetchContext');
        //</editor-fold>

        $newAuthz = $this->expectAuthzWithPartialLogin($user);

        $this->service->initialize($this->session);

        $this->assertSame($newAuthz, $this->service->authz());
        $this->assertEquals($timestamp, $this->service->time());
    }


    public function initalizedMethodProvider()
    {
        return [
            'is(...)' => ['is', 'foo'],
            'user()' => ['user'],
            'context()' => ['context'],
        ];
    }

    /**
     * @dataProvider initalizedMethodProvider
     * @group initialize
     */
    public function testAssertInitialized(string $method, ...$args)
    {
        $this->expectException(\LogicException::class);
        $this->service->{$method}(...$args);
    }

    /**
     * @group initialize
     */
    public function testForMultipleRequests()
    {
        $user = $this->createConfiguredMock(User::class, ['getAuthId' => '42', 'getAuthChecksum' => 'abc']);
        $apikey = $this->createConfiguredMock(User::class, ['getAuthId' => 'key:abc', 'getAuthChecksum' => '']);

        //<editor-fold desc="[prepare mocks]">
        $sessionOne = $this->createMock(Session::class);
        $sessionOne->expects($this->once())
            ->method('getInfo')
            ->willReturn(['user' => '42', 'context' => null, 'checksum' => 'abc', 'timestamp' => null]);

        $sessionTwo = $this->createMock(Session::class);
        $sessionTwo->expects($this->once())
            ->method('getInfo')
            ->willReturn(['user' => 'key:abc', 'context' => null, 'checksum' => '', 'timestamp' => null]);

        $this->storage->expects($this->exactly(2))->method('fetchUserById')
            ->withConsecutive(['42'], ['key:abc'])
            ->willReturnOnConsecutiveCalls($user, $apikey);

        $this->storage->expects($this->never())->method('fetchContext');

        $authzOne = $this->createMock(Authz::class);
        $authzTwo = $this->createMock(Authz::class);

        $this->authz->expects($this->exactly(2))->method('forUser')
            ->withConsecutive([$this->identicalTo($user)], [$this->identicalTo($apikey)])
            ->willReturnSelf();
        $this->authz->expects($this->exactly(2))->method('inContextOf')
            ->with(null)
            ->willReturnOnConsecutiveCalls($authzOne, $authzTwo);

        $authzOne->expects($this->once())->method('forUser')->with(null)->willReturnSelf();
        $authzOne->expects($this->once())->method('inContextOf')->with(null)->willReturn($this->authz);
        //</editor-fold>

        $service = $this->service->forMultipleRequests();
        $this->assertNotSame($this->service, $service);

        $service->initialize($sessionOne);
        $this->assertSame($authzOne, $service->authz());

        $service->initialize($sessionTwo);
        $this->assertSame($authzTwo, $service->authz());
    }


    public function testGetAvailableRoles()
    {
        $this->authz->expects($this->once())->method('getAvailableRoles')
            ->willReturn(['user', 'manager', 'admin']);

        $this->assertEquals(['user', 'manager', 'admin'], $this->service->getAvailableRoles());
    }

    public function testIsLoggedIn()
    {
        $this->authz->expects($this->exactly(2))->method('isLoggedIn')
            ->willReturnOnConsecutiveCalls(true, false);

        $this->assertTrue($this->service->isLoggedIn());
        $this->assertFalse($this->service->isLoggedIn());
    }

    public function testIsPartiallyLoggedIn()
    {
        $this->authz->expects($this->exactly(2))->method('isPartiallyLoggedIn')
            ->willReturnOnConsecutiveCalls(true, false);

        $this->assertTrue($this->service->isPartiallyLoggedIn());
        $this->assertFalse($this->service->isPartiallyLoggedIn());
    }

    public function testIsLoggedOut()
    {
        $this->authz->expects($this->exactly(2))->method('isLoggedOut')
            ->willReturnOnConsecutiveCalls(true, false);

        $this->assertTrue($this->service->isLoggedOut());
        $this->assertFalse($this->service->isLoggedOut());
    }

    public function testIs()
    {
        $this->authz->expects($this->exactly(2))->method('is')
            ->withConsecutive(['foo'], ['bar'])
            ->willReturn(true, false);

        $this->assertTrue($this->service->is('foo'));
        $this->assertFalse($this->service->is('bar'));
    }

    public function testUser()
    {
        $user = $this->createMock(User::class);
        $this->authz->expects($this->once())->method('user')->willReturn($user);

        $this->assertSame($user, $this->service->user());
    }

    public function testContext()
    {
        $context = $this->createMock(Context::class);
        $this->authz->expects($this->once())->method('context')->willReturn($context);

        $this->assertSame($context, $this->service->context());
    }

    public function testLoginAs()
    {
        //<editor-fold desc="[prepare mocks]">
        $user = $this->createConfiguredMock(
            User::class,
            ['getAuthId' => '42', 'getAuthChecksum' => 'abc', 'requiresMFA' => false]
        );

        $this->dispatcher->expects($this->once())->method('dispatch')
            ->with($this->callback(function ($event) use ($user) {
                $this->assertInstanceOf(Event\Login::class, $event);

                /** @var Event\Login $event */
                $this->assertSame($user, $event->user());
                return true;
            }))
            ->willReturnArgument(0);

        $this->storage->expects($this->once())->method('getContextForUser')->willReturn(null);

        $this->logger->expects($this->once())->method('info')
            ->with("Login successful", ['user' => '42']);

        $this->authz->expects($this->any())->method('isLoggedIn')->willReturn(false);
        $this->authz->expects($this->never())->method('user');
        $newAuthz = $this->expectSetAuthzUser($user);
        $newAuthz->expects($this->once())->method('inContextOf')->with(null)->willReturnSelf();

        $this->session->expects($this->once())->method('persist')
            ->with('42', null, 'abc', $this->isInstanceOf(\DateTimeInterface::class));
        //</editor-fold>

        $this->service->loginAs($user);

        $this->assertSame($newAuthz, $this->service->authz());
    }

    public function testLoginAsWithPartialLogin()
    {
        //<editor-fold desc="[prepare mocks]">
        $user = $this->createConfiguredMock(
            User::class,
            ['getAuthId' => '42', 'getAuthChecksum' => 'abc', 'requiresMFA' => true]
        );

        $this->dispatcher->expects($this->once())->method('dispatch')
            ->with($this->callback(function ($event) use ($user) {
                $this->assertInstanceOf(Event\PartialLogin::class, $event);
                $this->assertSame($user, $event->user());
                return true;
            }))
            ->willReturnArgument(0);

        $this->storage->expects($this->never())->method('getContextForUser');

        $this->logger->expects($this->once())->method('info')
            ->with("Partial login", ['user' => '42']);

        $this->authz->expects($this->any())->method('isLoggedIn')->willReturn(false);
        $this->authz->expects($this->never())->method('user');

        $newAuthz = $this->expectAuthzWithPartialLogin($user);

        $this->session->expects($this->once())->method('persist')
            ->with('#partial:42', null, 'abc', $this->isInstanceOf(\DateTimeInterface::class));
        $this->storage->expects($this->never())->method('getContextForUser');
        //</editor-fold>

        $this->service->loginAs($user);

        $this->assertSame($newAuthz, $this->service->authz());
    }

    public function testCancelLogin()
    {
        $user = $this->createConfiguredMock(
            User::class,
            ['getAuthId' => '42', 'getAuthChecksum' => 'abc', 'requiresMFA' => false]
        );

        $this->dispatcher->expects($this->once())->method('dispatch')
            ->with($this->callback(function (Event\Login $event) {
                $event->cancel('no good');
                return true;
            }))
            ->willReturnArgument(0);

        //<editor-fold desc="[prepare mocks]">
        $this->authz->expects($this->any())->method('isLoggedIn')->willReturn(false);
        $this->authz->expects($this->never())->method('user');
        $this->authz->expects($this->never())->method('forUser');
        $this->authz->expects($this->never())->method('inContextOf');
        $this->session->expects($this->never())->method('persist');

        $this->expectException(LoginException::class);
        $this->expectExceptionMessage('no good');
        $this->expectExceptionCode(LoginException::CANCELLED);
        //</editor-fold>

        $this->service->loginAs($user);
    }

    public function testLoginAsTwice()
    {
        $user = $this->createMock(User::class);

        //<editor-fold desc="[prepare mocks]">
        $this->authz->expects($this->any())->method('isLoggedIn')->willReturn(true);
        $this->authz->expects($this->any())->method('user')->willReturn($user);

        $this->expectException(\LogicException::class);
        //</editor-fold>

        $this->service->loginAs($user);
    }

    public function testLoginAsWithDefaultContext()
    {
        //<editor-fold desc="[prepare mocks]">
        $user = $this->createConfiguredMock(
            User::class,
            ['getAuthId' => '42', 'getAuthChecksum' => 'abc', 'requiresMFA' => false]
        );

        $context = $this->createConfiguredMock(Context::class, ['getAuthId' => 'foo']);

        $this->dispatcher->expects($this->once())->method('dispatch')
            ->with($this->callback(function ($event) use ($user) {
                $this->assertInstanceOf(Event\Login::class, $event);

                /** @var Event\Login $event */
                $this->assertSame($user, $event->user());
                return true;
            }))
            ->willReturnArgument(0);

        $this->storage->expects($this->once())->method('getContextForUser')->willReturn($context);

        $newAuthz = $this->createNewAuthzMock($user, $context);

        $this->authz->expects($this->any())->method('isLoggedIn')->willReturn(false);
        $this->authz->expects($this->never())->method('user');
        $userAuthz = $this->expectSetAuthzUser($user);
        $userAuthz->expects($this->once())->method('inContextOf')->with($context)->willReturn($newAuthz);

        $this->session->expects($this->once())->method('persist')
            ->with('42', 'foo', 'abc', $this->isInstanceOf(\DateTimeInterface::class));
        //</editor-fold>

        $this->service->loginAs($user);

        $this->assertSame($newAuthz, $this->service->authz());
    }


    public function testLogin()
    {
        $user = $this->createMock(User::class);
        $user->expects($this->once())->method('verifyPassword')
            ->with('pwd')
            ->willReturn(true);

        $this->storage->expects($this->once())->method('fetchUserByUsername')
            ->with('john')
            ->willReturn($user);

        //<editor-fold desc="[prepare mocks]">
        $user->expects($this->any())->method('getAuthId')->willReturn('42');
        $user->expects($this->any())->method('getAuthChecksum')->willReturn('xyz');
        $user->expects($this->any())->method('requiresMFA')->willReturn(false);

        $this->dispatcher->expects($this->once())->method('dispatch')
            ->with($this->callback(function ($event) use ($user) {
                $this->assertInstanceOf(Event\Login::class, $event);

                /** @var Event\Login $event */
                $this->assertSame($user, $event->user());
                return true;
            }))
            ->willReturnArgument(0);

        $this->storage->expects($this->once())->method('getContextForUser')->willReturn(null);

        $this->logger->expects($this->once())->method('info')
            ->with("Login successful", ['user' => '42']);

        $this->authz->expects($this->any())->method('isLoggedIn')->willReturn(false);
        $this->authz->expects($this->never())->method('user');
        $newAuthz = $this->expectSetAuthzUser($user);
        $newAuthz->expects($this->once())->method('inContextOf')->with(null)->willReturnSelf();

        $this->session->expects($this->once())->method('persist')
            ->with('42', null, 'xyz', $this->isInstanceOf(\DateTimeInterface::class));
        //</editor-fold>

        $this->service->login('john', 'pwd');

        $this->assertSame($newAuthz, $this->service->authz());
    }

    public function testLoginWithIncorrectUsername()
    {
        $this->storage->expects($this->once())->method('fetchUserByUsername')
            ->with('john')
            ->willReturn(null);

        //<editor-fold desc="[prepare mocks]">
        $this->dispatcher->expects($this->never())->method('dispatch');

        $this->logger->expects($this->once())->method('debug')
            ->with("Login failed: invalid credentials", ['username' => 'john']);

        $this->authz->expects($this->any())->method('isLoggedIn')->willReturn(false);
        $this->authz->expects($this->never())->method('user');
        $this->authz->expects($this->never())->method('forUser');
        $this->authz->expects($this->never())->method('inContextOf');
        $this->session->expects($this->never())->method('persist');

        $this->expectException(LoginException::class);
        $this->expectExceptionMessage('Invalid credentials');
        $this->expectExceptionCode(LoginException::INVALID_CREDENTIALS);
        //</editor-fold>

        $this->service->login('john', 'pwd');
    }

    public function testLoginWithInvalidPassword()
    {
        $user = $this->createMock(User::class);
        $user->expects($this->once())->method('verifyPassword')
            ->with('pwd')
            ->willReturn(false);

        //<editor-fold desc="[prepare mocks]">
        $user->expects($this->any())->method('getAuthId')->willReturn('42');
        $user->expects($this->any())->method('getAuthChecksum')->willReturn('abc');
        $user->expects($this->never())->method('requiresMFA');

        $this->storage->expects($this->once())->method('fetchUserByUsername')
            ->with('john')
            ->willReturn($user);

        $this->dispatcher->expects($this->never())->method('dispatch');

        $this->logger->expects($this->once())->method('debug')
            ->with("Login failed: invalid credentials", ['username' => 'john']);

        $this->authz->expects($this->any())->method('isLoggedIn')->willReturn(false);
        $this->authz->expects($this->never())->method('user');
        $this->authz->expects($this->never())->method('forUser');
        $this->authz->expects($this->never())->method('inContextOf');
        $this->session->expects($this->never())->method('persist');
        //</editor-fold>

        $this->expectException(LoginException::class);
        $this->expectExceptionMessage('Invalid credentials');
        $this->expectExceptionCode(LoginException::INVALID_CREDENTIALS);

        $this->service->login('john', 'pwd');
    }

    public function testLoginTwice()
    {
        //<editor-fold desc="[prepare mocks]">
        $user = $this->createMock(User::class);
        $this->authz->expects($this->any())->method('isLoggedIn')->willReturn(true);
        $this->authz->expects($this->any())->method('user')->willReturn($user);
        //</editor-fold>

        $this->expectException(\LogicException::class);

        $this->service->login('john', 'pwd');
    }

    public function testLogout()
    {
        //<editor-fold desc="[prepare mocks]">
        $user = $this->createMock(User::class);
        $user->expects($this->any())->method('getAuthId')->willReturn('42');

        $this->dispatcher->expects($this->once())->method('dispatch')
            ->with($this->callback(function ($event) use ($user) {
                $this->assertInstanceOf(Event\Logout::class, $event);

                /** @var Event\Login $event */
                $this->assertSame($user, $event->user());
                return true;
            }))
            ->willReturnArgument(0);

        $this->logger->expects($this->once())->method('debug')
            ->with("Logout", ['user' => '42']);

        $this->authz->expects($this->any())->method('isLoggedIn')->willReturn(true);
        $this->authz->expects($this->any())->method('user')->willReturn($user);
        $this->session->expects($this->once())->method('clear');
        //</editor-fold>

        $newAuthz = $this->expectInitAuthz(null, null);

        $this->service->logout();

        $this->assertSame($newAuthz, $this->service->authz());
    }

    public function testLogoutTwice()
    {
        $this->authz->expects($this->any())->method('isLoggedIn')->willReturn(false);
        $this->authz->expects($this->never())->method('user');
        $this->authz->expects($this->never())->method('forUser');
        $this->authz->expects($this->never())->method('inContextOf');
        $this->session->expects($this->never())->method('persist');

        $this->service->logout();
    }

    public function testPartialLogin()
    {
        $user = $this->createMock(User::class);
        $user->expects($this->once())->method('verifyPassword')
            ->with('pwd')
            ->willReturn(true);
        $user->expects($this->any())->method('requiresMFA')->willReturn(true);

        $this->storage->expects($this->once())->method('fetchUserByUsername')
            ->with('john')
            ->willReturn($user);

        //<editor-fold desc="[prepare mocks]">
        $user->expects($this->any())->method('getAuthId')->willReturn('42');
        $user->expects($this->any())->method('getAuthChecksum')->willReturn('xyz');

        $this->dispatcher->expects($this->once())->method('dispatch')
            ->with($this->callback(function ($event) use ($user) {
                $this->assertInstanceOf(Event\PartialLogin::class, $event);
                $this->assertSame($user, $event->user());
                return true;
            }))
            ->willReturnArgument(0);

        $this->storage->expects($this->never())->method('getContextForUser');

        $this->logger->expects($this->once())->method('info')
            ->with("Partial login", ['user' => '42']);

        $this->authz->expects($this->any())->method('isLoggedIn')->willReturn(false);
        $this->authz->expects($this->never())->method('user');

        $newAuthz = $this->expectAuthzWithPartialLogin($user);

        $this->session->expects($this->once())->method('persist')
            ->with('#partial:42', null, 'xyz', $this->isInstanceOf(\DateTimeInterface::class));
        //</editor-fold>

        $this->service->login('john', 'pwd');

        $this->assertSame($newAuthz, $this->service->authz());
    }

    public function testPartialLoginAs()
    {
        $user = $this->createMock(User::class);
        $user->expects($this->any())->method('requiresMFA')->willReturn(true);

        //<editor-fold desc="[prepare mocks]">
        $user->expects($this->any())->method('getAuthId')->willReturn('42');
        $user->expects($this->any())->method('getAuthChecksum')->willReturn('xyz');

        $this->dispatcher->expects($this->once())->method('dispatch')
            ->with($this->callback(function ($event) use ($user) {
                $this->assertInstanceOf(Event\PartialLogin::class, $event);
                $this->assertSame($user, $event->user());
                return true;
            }))
            ->willReturnArgument(0);

        $this->storage->expects($this->never())->method('getContextForUser');

        $this->logger->expects($this->once())->method('info')
            ->with("Partial login", ['user' => '42']);

        $this->authz->expects($this->any())->method('isLoggedIn')->willReturn(false);
        $this->authz->expects($this->never())->method('user');

        $newAuthz = $this->expectAuthzWithPartialLogin($user);

        $this->session->expects($this->once())->method('persist')
            ->with('#partial:42', null, 'xyz', $this->isInstanceOf(\DateTimeInterface::class));
        //</editor-fold>

        $this->service->loginAs($user);

        $this->assertSame($newAuthz, $this->service->authz());
    }

    public function testCancelPartialLogin()
    {
        $user = $this->createMock(User::class);
        $user->expects($this->once())->method('requiresMFA')->willReturn(true);

        $this->dispatcher->expects($this->once())->method('dispatch')
            ->with($this->callback(function ($event) {
                $this->assertInstanceOf(Event\PartialLogin::class, $event);
                $event->cancel('no good');
                return true;
            }))
            ->willReturnArgument(0);

        //<editor-fold desc="[prepare mocks]">
        $user->expects($this->any())->method('getAuthId')->willReturn('42');
        $user->expects($this->any())->method('getAuthChecksum')->willReturn('xyz');

        $this->authz->expects($this->any())->method('isLoggedIn')->willReturn(false);
        $this->authz->expects($this->never())->method('user');
        $this->authz->expects($this->never())->method('forUser');
        $this->authz->expects($this->never())->method('inContextOf');
        $this->session->expects($this->never())->method('persist');

        $this->expectException(LoginException::class);
        $this->expectExceptionMessage('no good');
        $this->expectExceptionCode(LoginException::CANCELLED);
        //</editor-fold>

        $this->service->loginAs($user);
    }


    public function testMfaWhenPartiallyLoggedIn()
    {
        $user = $this->createConfiguredMock(User::class, ['getAuthId' => '42', 'getAuthChecksum' => 'abc']);
        $partial = new PartiallyLoggedIn($user);

        //<editor-fold desc="[prepare mocks]">
        $this->authz->expects($this->any())->method('isLoggedIn')->willReturn(false);
        $this->authz->expects($this->any())->method('isPartiallyLoggedIn')->willReturn(true);
        $this->authz->expects($this->any())->method('isLoggedOut')->willReturn(false);
        $this->authz->expects($this->atLeastOnce())->method('user')->willReturn($partial);

        $service = $this->service->withMFA(function($mfaUser, $mfaCode) use ($user): bool  {
            $this->assertSame($user, $mfaUser);
            $this->assertSame("123890", $mfaCode);

            return true;
        });

        $this->dispatcher->expects($this->once())->method('dispatch')
            ->with($this->callback(function ($event) use ($user) {
                $this->assertInstanceOf(Event\Login::class, $event);

                /** @var Event\Login $event */
                $this->assertSame($user, $event->user());
                return true;
            }))
            ->willReturnArgument(0);

        $this->storage->expects($this->once())->method('getContextForUser')->willReturn(null);

        $this->logger->expects($this->once())->method('info')
            ->with("Login successful", ['user' => '42']);

        $newAuthz = $this->expectSetAuthzUser($user);
        $newAuthz->expects($this->once())->method('inContextOf')->with(null)->willReturnSelf();

        $this->session->expects($this->once())->method('persist')
            ->with('42', null, 'abc', $this->isInstanceOf(\DateTimeInterface::class));
        //</editor-fold>

        $service->mfa("123890");

        $this->assertSame($newAuthz, $service->authz());

        $this->assertInstanceOf(\DateTimeInterface::class, $service->time());
        $this->assertEqualsWithDelta(time(), $service->time()->getTimestamp(), 5);
    }

    public function testMfaWhenLoggedIn()
    {
        $user = $this->createConfiguredMock(User::class, ['getAuthId' => '42', 'getAuthChecksum' => 'abc']);

        //<editor-fold desc="[prepare mocks]">
        $this->authz->expects($this->any())->method('isLoggedIn')->willReturn(true);
        $this->authz->expects($this->any())->method('isPartiallyLoggedIn')->willReturn(false);
        $this->authz->expects($this->any())->method('isLoggedOut')->willReturn(false);
        $this->authz->expects($this->atLeastOnce())->method('user')->willReturn($user);

        $this->setPrivateProperty($this->service, 'timestamp', new \DateTimeImmutable('2020-01-01T00:00:00+00:00'));

        $service = $this->service->withMFA(function($mfaUser, $mfaCode) use ($user): bool  {
            $this->assertSame($user, $mfaUser);
            $this->assertSame("123890", $mfaCode);

            return true;
        });

        $this->dispatcher->expects($this->never())->method('dispatch');

        $this->logger->expects($this->once())->method('info')
            ->with("MFA verification successful", ['user' => '42']);

        $this->session->expects($this->never())->method('persist');
        //</editor-fold>

        $service->mfa("123890");

        $this->assertSame($this->authz, $service->authz());
        $this->assertEquals(new \DateTimeImmutable('2020-01-01T00:00:00+00:00'), $service->time());
    }

    public function testMfaWhenLoggedOut()
    {
        //<editor-fold desc="[prepare mocks]">
        $this->authz->expects($this->any())->method('isLoggedIn')->willReturn(false);
        $this->authz->expects($this->any())->method('isPartiallyLoggedIn')->willReturn(false);
        $this->authz->expects($this->any())->method('isLoggedOut')->willReturn(true);
        $this->authz->expects($this->never())->method('user');

        $service = $this->service->withMFA($this->createCallbackMock($this->never()));
        //</editor-fold>

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage("Unable to perform MFA verification: No user (partially) logged in");

        $service->mfa("123890");
    }

    public function mfaUserProvider()
    {
        $user = $this->createConfiguredMock(User::class, ['getAuthId' => '42', 'getAuthChecksum' => 'abc']);
        $partial = new PartiallyLoggedIn($user);

        return [
            [$partial, $user],
            [$user, $user],
        ];
    }

    /**
     * @dataProvider mfaUserProvider
     */
    public function testMfaWithInvalidCode($authzUser, $user)
    {
        //<editor-fold desc="[prepare mocks]">
        $this->authz->expects($this->any())->method('isLoggedIn')->willReturn(false);
        $this->authz->expects($this->any())->method('isPartiallyLoggedIn')->willReturn(true);
        $this->authz->expects($this->any())->method('isLoggedOut')->willReturn(false);
        $this->authz->expects($this->atLeastOnce())->method('user')->willReturn($authzUser);

        $service = $this->service->withMFA(function($mfaUser, $mfaCode) use ($user): bool  {
            $this->assertSame($user, $mfaUser);
            $this->assertSame("000000", $mfaCode);

            return false;
        });

        $this->dispatcher->expects($this->never())->method('dispatch');
        $this->storage->expects($this->never())->method('getContextForUser');

        $this->logger->expects($this->once())->method('debug')
            ->with("MFA verification failed", ['user' => '42']);

        $this->session->expects($this->never())->method('persist');
        //</editor-fold>

        $this->expectException(LoginException::class);
        $this->expectExceptionMessage('Invalid MFA');
        $this->expectExceptionCode(LoginException::INVALID_CREDENTIALS);

        $service->mfa("000000");
    }


    public function testSetContext()
    {
        $user = $this->createConfiguredMock(User::class, ['getAuthId' => '42', 'getAuthChecksum' => 'abc']);
        $context = $this->createConfiguredMock(Context::class, ['getAuthId' => 'foo']);

        //<editor-fold desc="[prepare mocks]">
        $timestamp = new \DateTimeImmutable('2020-01-01T00:00:00+00:00');
        $this->setPrivateProperty($this->service, 'timestamp', $timestamp);

        $this->authz->expects($this->any())->method('isLoggedIn')->willReturn(true);
        $this->authz->expects($this->any())->method('user')->willReturn($user);

        $this->session->expects($this->once())->method('persist')
            ->with('42', 'foo', 'abc', $timestamp);
        //</editor-fold>

        $newAuthz = $this->expectSetAuthzContext($user, $context);

        $this->service->setContext($context);

        $this->assertSame($newAuthz, $this->service->authz());
    }

    public function testClearContext()
    {
        $user = $this->createConfiguredMock(User::class, ['getAuthId' => '42', 'getAuthChecksum' => 'abc']);

        //<editor-fold desc="[prepare mocks]">
        $this->authz->expects($this->any())->method('isLoggedIn')->willReturn(true);
        $this->authz->expects($this->any())->method('user')->willReturn($user);

        $this->session->expects($this->once())->method('persist')
            ->with('42', null, 'abc', null);
        //</editor-fold>

        $newAuthz = $this->expectSetAuthzContext($user, null);

        $this->service->setContext(null);

        $this->assertSame($newAuthz, $this->service->authz());
    }

    public function testRecalc()
    {
        $user = $this->createConfiguredMock(User::class, ['getAuthId' => '42', 'getAuthChecksum' => 'abc']);
        $context = $this->createConfiguredMock(Context::class, ['getAuthId' => 'foo']);

        $newAuthz = $this->createNewAuthzMock($user, $context);
        $this->authz->expects($this->once())->method('recalc')->willReturn($newAuthz);

        //<editor-fold desc="[prepare mocks]">
        $this->authz->expects($this->never())->method('user');
        $this->authz->expects($this->never())->method('context');

        $this->session->expects($this->never())->method('clear');
        $this->session->expects($this->once())->method('persist')
            ->with('42', 'foo', 'abc', null);
        //</editor-fold>

        $this->service->recalc();
    }

    public function testRecalcWithoutUser()
    {
        //<editor-fold desc="[prepare mocks]">
        $this->authz->expects($this->once())->method('recalc')->willReturnSelf();
        $this->authz->expects($this->any())->method('isLoggedIn')->willReturn(false);
        $this->authz->expects($this->any())->method('isLoggedOut')->willReturn(true);
        $this->authz->expects($this->never())->method('user');
        $this->authz->expects($this->any())->method('context')->willReturn(null);

        $this->session->expects($this->once())->method('clear');
        $this->session->expects($this->never())->method('persist');
        //</editor-fold>

        $this->service->recalc();
    }


    public function testForUser()
    {
        $user = $this->createMock(User::class);
        $newAuthz = $this->createMock(Authz::class);

        $this->authz->expects($this->once())->method('forUser')
            ->with($user)
            ->willReturn($newAuthz);

        $this->assertSame($newAuthz, $this->service->forUser($user));
        $this->assertSame($this->authz, $this->service->authz()); // Not modified
    }

    public function testForContext()
    {
        $context = $this->createMock(Context::class);
        $newAuthz = $this->createMock(Authz::class);

        $this->authz->expects($this->once())->method('inContextOf')
            ->with($context)
            ->willReturn($newAuthz);

        $this->assertSame($newAuthz, $this->service->inContextOf($context));
        $this->assertSame($this->authz, $this->service->authz()); // Not modified
    }


    public function testConfirm()
    {
        $newConfirmation = $this->createMock(Confirmation::class);
        $newConfirmation->expects($this->never())->method($this->anything());

        $this->confirmation->expects($this->once())->method('withStorage')
            ->with($this->identicalTo($this->storage))
            ->willReturnSelf();

        $this->confirmation->expects($this->once())->method('withLogger')
            ->with($this->identicalTo($this->logger))
            ->willReturnSelf();

        $this->confirmation->expects($this->once())->method('withSubject')
            ->with('foo bar')
            ->willReturn($newConfirmation);

        $this->assertSame($newConfirmation, $this->service->confirm('foo bar'));
    }
}
