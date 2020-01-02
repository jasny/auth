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
use Jasny\Auth\UserInterface as User;
use Jasny\PHPUnit\PrivateAccessTrait;
use PHPStan\Testing\TestCase;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\EventDispatcher\EventDispatcherInterface as EventDispatcher;

/**
 * @covers \Jasny\Auth\Auth
 */
class AuthTest extends TestCase
{
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

    public function setUp(): void
    {
        $this->authz = $this->createMock(Authz::class);
        $this->storage = $this->createMock(Storage::class);
        $this->confirmation = $this->createMock(Confirmation::class);
        $this->session = $this->createMock(Session::class);
        $this->dispatcher = $this->createMock(EventDispatcher::class);

        $this->service = (new Auth($this->authz, $this->storage, $this->confirmation))
            ->withEventDispatcher($this->dispatcher);

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

        if ($user === null) {
            $newAuthz->expects($this->any())->method('isLoggedIn')->willReturn(false);
            $newAuthz->expects($this->never())->method('user');
        } else {
            $newAuthz->expects($this->any())->method('isLoggedIn')->willReturn(true);
            $newAuthz->expects($this->any())->method('user')->willReturn($user);
        }

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
     * @group initialize
     */
    public function testInitializeWithoutSession()
    {
        //<editor-fold desc="[prepare mocks]">
        $this->session->expects($this->once())
            ->method('getInfo')
            ->willReturn(['user' => null, 'context' => null, 'checksum' => null]);

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
        $user = $this->createConfiguredMock(User::class, ['getAuthId' => 42, 'getAuthChecksum' => 'abc']);

        //<editor-fold desc="[prepare mocks]">
        $this->session->expects($this->once())
            ->method('getInfo')
            ->willReturn(['user' => 42, 'context' => null, 'checksum' => 'abc']);

        $this->storage->expects($this->once())->method('fetchUserById')
            ->with(42)
            ->willReturn($user);
        $this->storage->expects($this->never())->method('fetchContext');
        //</editor-fold>

        $newAuthz = $this->expectInitAuthz($user, null);

        $this->service->initialize($this->session);

        $this->assertSame($newAuthz, $this->service->authz());
    }

    /**
     * @group initialize
     */
    public function testInitializeWithUserAndContext()
    {
        $user = $this->createConfiguredMock(User::class, ['getAuthId' => 42, 'getAuthChecksum' => 'abc']);
        $context = $this->createConfiguredMock(Context::class, ['getAuthId' => 'foo']);

        //<editor-fold desc="[prepare mocks]">
        $this->session->expects($this->once())
            ->method('getInfo')
            ->willReturn(['user' => 42, 'context' => 'foo', 'checksum' => 'abc']);

        $this->storage->expects($this->once())->method('fetchUserById')
            ->with(42)
            ->willReturn($user);
        $this->storage->expects($this->once())->method('fetchContext')
            ->with('foo')
            ->willReturn($context);
        //</editor-fold>

        $newAuthz = $this->expectInitAuthz($user, $context);

        $this->service->initialize($this->session);

        $this->assertSame($newAuthz, $this->service->authz());
    }

    /**
     * @group initialize
     */
    public function testInitializeWithUserAndContextObjects()
    {
        $user = $this->createConfiguredMock(User::class, ['getAuthId' => 42, 'getAuthChecksum' => 'abc']);
        $context = $this->createConfiguredMock(Context::class, ['getAuthId' => 'foo']);

        //<editor-fold desc="[prepare mocks]">
        $this->session->expects($this->once())
            ->method('getInfo')
            ->willReturn(['user' => $user, 'context' => $context, 'checksum' => 'abc']);

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
        $user = $this->createConfiguredMock(User::class, ['getAuthId' => 42, 'getAuthChecksum' => 'xyz']);

        //<editor-fold desc="[prepare mocks]">
        $this->session->expects($this->once())
            ->method('getInfo')
            ->willReturn(['user' => 42, 'context' => null, 'checksum' => 'abc']);

        $this->storage->expects($this->once())->method('fetchUserById')
            ->with(42)
            ->willReturn($user);
        $this->storage->expects($this->never())->method('fetchContext');
        //</editor-fold>

        $newAuthz = $this->expectInitAuthz(null, null);

        $this->service->initialize($this->session);

        $this->assertSame($newAuthz, $this->service->authz());
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
        $user = $this->createConfiguredMock(User::class, ['getAuthId' => 42, 'getAuthChecksum' => 'abc']);
        $apikey = $this->createConfiguredMock(User::class, ['getAuthId' => 'key:abc', 'getAuthChecksum' => '']);

        //<editor-fold desc="[prepare mocks]">
        $sessionOne = $this->createMock(Session::class);
        $sessionOne->expects($this->once())
            ->method('getInfo')
            ->willReturn(['user' => 42, 'context' => null, 'checksum' => 'abc']);

        $sessionTwo = $this->createMock(Session::class);
        $sessionTwo->expects($this->once())
            ->method('getInfo')
            ->willReturn(['user' => 'key:abc', 'context' => null, 'checksum' => '']);

        $this->storage->expects($this->exactly(2))->method('fetchUserById')
            ->withConsecutive([42], ['key:abc'])
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
        $this->authz->expects($this->once())->method('isLoggedIn')
            ->willReturn(true);

        $this->assertTrue($this->service->isLoggedIn());
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
        $user = $this->createConfiguredMock(User::class, ['getAuthId' => 42, 'getAuthChecksum' => 'abc']);

        $this->dispatcher->expects($this->once())->method('dispatch')
            ->with($this->callback(function ($event) use ($user) {
                $this->assertInstanceOf(Event\Login::class, $event);

                /** @var Event\Login $event */
                $this->assertSame($user, $event->user());
                return true;
            }))
            ->willReturnArgument(0);

        $this->storage->expects($this->once())->method('getContextForUser')->willReturn(null);

        $this->authz->expects($this->any())->method('isLoggedIn')->willReturn(false);
        $this->authz->expects($this->never())->method('user');
        $newAuthz = $this->expectSetAuthzUser($user);
        $newAuthz->expects($this->once())->method('inContextOf')->with(null)->willReturnSelf();

        $this->session->expects($this->once())->method('persist')
            ->with(42, null, 'abc');
        //</editor-fold>

        $this->service->loginAs($user);
    }

    public function testCancelLogin()
    {
        $user = $this->createConfiguredMock(User::class, ['getAuthId' => 42, 'getAuthChecksum' => 'abc']);

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
        $user = $this->createConfiguredMock(User::class, ['getAuthId' => 42, 'getAuthChecksum' => 'abc']);
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
            ->with(42, 'foo', 'abc');
        //</editor-fold>

        $this->service->loginAs($user);
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
        $user->expects($this->any())->method('getAuthId')->willReturn(42);
        $user->expects($this->any())->method('getAuthChecksum')->willReturn('xyz');

        $this->dispatcher->expects($this->once())->method('dispatch')
            ->with($this->callback(function ($event) use ($user) {
                $this->assertInstanceOf(Event\Login::class, $event);

                /** @var Event\Login $event */
                $this->assertSame($user, $event->user());
                return true;
            }))
            ->willReturnArgument(0);

        $this->storage->expects($this->once())->method('getContextForUser')->willReturn(null);

        $this->authz->expects($this->any())->method('isLoggedIn')->willReturn(false);
        $this->authz->expects($this->never())->method('user');
        $newAuthz = $this->expectSetAuthzUser($user);
        $newAuthz->expects($this->once())->method('inContextOf')->with(null)->willReturnSelf();

        $this->session->expects($this->once())->method('persist')
            ->with(42, null, 'xyz');
        //</editor-fold>

        $this->service->login('john', 'pwd');
    }

    public function testLoginWithIncorrectUsername()
    {
        $this->storage->expects($this->once())->method('fetchUserByUsername')
            ->with('john')
            ->willReturn(null);

        //<editor-fold desc="[prepare mocks]">
        $this->dispatcher->expects($this->never())->method('dispatch');

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
        $user->expects($this->any())->method('getAuthId')->willReturn(42);
        $user->expects($this->any())->method('getAuthChecksum')->willReturn('abc');

        $this->storage->expects($this->once())->method('fetchUserByUsername')
            ->with('john')
            ->willReturn($user);

        $this->dispatcher->expects($this->never())->method('dispatch');

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

        $this->dispatcher->expects($this->once())->method('dispatch')
            ->with($this->callback(function ($event) use ($user) {
                $this->assertInstanceOf(Event\Logout::class, $event);

                /** @var Event\Login $event */
                $this->assertSame($user, $event->user());
                return true;
            }))
            ->willReturnArgument(0);

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

    public function testSetContext()
    {
        $user = $this->createConfiguredMock(User::class, ['getAuthId' => 42, 'getAuthChecksum' => 'abc']);
        $context = $this->createConfiguredMock(Context::class, ['getAuthId' => 'foo']);

        //<editor-fold desc="[prepare mocks]">
        $this->authz->expects($this->any())->method('isLoggedIn')->willReturn(true);
        $this->authz->expects($this->any())->method('user')->willReturn($user);

        $this->session->expects($this->once())->method('persist')
            ->with(42, 'foo', 'abc');
        //</editor-fold>

        $newAuthz = $this->expectSetAuthzContext($user, $context);

        $this->service->setContext($context);

        $this->assertSame($newAuthz, $this->service->authz());
    }

    public function testClearContext()
    {
        $user = $this->createConfiguredMock(User::class, ['getAuthId' => 42, 'getAuthChecksum' => 'abc']);

        //<editor-fold desc="[prepare mocks]">
        $this->authz->expects($this->any())->method('isLoggedIn')->willReturn(true);
        $this->authz->expects($this->any())->method('user')->willReturn($user);

        $this->session->expects($this->once())->method('persist')
            ->with(42, null, 'abc');
        //</editor-fold>

        $newAuthz = $this->expectSetAuthzContext($user, null);

        $this->service->setContext(null);

        $this->assertSame($newAuthz, $this->service->authz());
    }

    public function testRecalc()
    {
        $user = $this->createConfiguredMock(User::class, ['getAuthId' => 42, 'getAuthChecksum' => 'abc']);
        $context = $this->createConfiguredMock(Context::class, ['getAuthId' => 'foo']);

        $newAuthz = $this->createNewAuthzMock($user, $context);
        $this->authz->expects($this->once())->method('recalc')->willReturn($newAuthz);

        //<editor-fold desc="[prepare mocks]">
        $this->authz->expects($this->never())->method('user');
        $this->authz->expects($this->never())->method('context');


        $this->session->expects($this->never())->method('clear');
        $this->session->expects($this->once())->method('persist')
            ->with(42, 'foo', 'abc');
        //</editor-fold>

        $this->service->recalc();
    }

    public function testRecalcWithoutUser()
    {
        //<editor-fold desc="[prepare mocks]">
        $this->authz->expects($this->once())->method('recalc')->willReturnSelf();
        $this->authz->expects($this->any())->method('isLoggedIn')->willReturn(false);
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

        $this->confirmation->expects($this->once())->method('withStorage')
            ->with($this->identicalTo($this->storage))
            ->willReturnSelf();

        $this->confirmation->expects($this->once())->method('withSubject')
            ->with('foo bar')
            ->willReturn($newConfirmation);

        $this->assertSame($newConfirmation, $this->service->confirm('foo bar'));
    }
}
