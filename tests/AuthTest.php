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
        $this->session = $this->createMock(Session::class);
        $this->storage = $this->createMock(Storage::class);
        $this->confirmation = $this->createMock(Confirmation::class);
        $this->dispatcher = $this->createMock(EventDispatcher::class);

        $this->service = (new Auth($this->authz, $this->storage, $this->confirmation))
            ->withSession($this->session)
            ->withEventDispatcher($this->dispatcher);
    }


    protected function expectInitAuthz(?User $user, ?Context $context)
    {
        $newAuthz = $this->createMock(Authz::class);

        $this->authz->expects($this->once())->method('forUser')
            ->with($this->identicalTo($user))
            ->willReturnSelf();
        $this->authz->expects($this->once())->method('inContextOf')
            ->with($this->identicalTo($context))
            ->willReturn($newAuthz);

        return $newAuthz;
    }

    public function testInitializeWithoutSession()
    {
        //<editor-fold desc="[prepare mocks]">
        $this->session->expects($this->once())
            ->method('getInfo')
            ->willReturn(['uid' => null, 'context' => null, 'checksum' => null]);

        $this->storage->expects($this->never())->method($this->anything());

        $newAuthz = $this->expectInitAuthz(null, null);
        //</editor-fold>

        $this->service->initialize();

        $this->assertSame($newAuthz, $this->service->authz());

        return $this->service;
    }

    /**
     * @depends testInitializeWithoutSession
     */
    public function testInitializeTwice(Auth $service)
    {
        $this->expectException(\LogicException::class);
        $service->initialize();
    }

    public function testInitializeWithUser()
    {
        $user = $this->createConfiguredMock(User::class, ['getId' => 42, 'getAuthChecksum' => 'abc']);

        //<editor-fold desc="[prepare mocks]">
        $this->session->expects($this->once())
            ->method('getInfo')
            ->willReturn(['uid' => 42, 'context' => null, 'checksum' => 'abc']);

        $this->storage->expects($this->once())->method('fetchUserById')
            ->with(42)
            ->willReturn($user);
        $this->storage->expects($this->never())->method('fetchContext');

        $newAuthz = $this->expectInitAuthz($user, null);
        //</editor-fold>

        $this->service->initialize();

        $this->assertSame($newAuthz, $this->service->authz());
    }

    public function testInitializeWithUserAndContext()
    {
        $user = $this->createConfiguredMock(User::class, ['getId' => 42, 'getAuthChecksum' => 'abc']);
        $context = $this->createConfiguredMock(Context::class, ['getId' => 'foo']);

        //<editor-fold desc="[prepare mocks]">
        $this->session->expects($this->once())
            ->method('getInfo')
            ->willReturn(['uid' => 42, 'context' => 'foo', 'checksum' => 'abc']);

        $this->storage->expects($this->once())->method('fetchUserById')
            ->with(42)
            ->willReturn($user);
        $this->storage->expects($this->once())->method('fetchContext')
            ->with('foo')
            ->willReturn($context);

        $newAuthz = $this->expectInitAuthz($user, $context);
        //</editor-fold>

        $this->service->initialize();

        $this->assertSame($newAuthz, $this->service->authz());

        return $this->service;
    }

    public function testInitializeWithInvalidAuthChecksum()
    {
        $user = $this->createConfiguredMock(User::class, ['getId' => 42, 'getAuthChecksum' => 'xyz']);

        //<editor-fold desc="[prepare mocks]">
        $this->session->expects($this->once())
            ->method('getInfo')
            ->willReturn(['uid' => 42, 'context' => null, 'checksum' => 'abc']);

        $this->storage->expects($this->once())->method('fetchUserById')
            ->with(42)
            ->willReturn($user);
        $this->storage->expects($this->never())->method('fetchContext');

        $newAuthz = $this->expectInitAuthz(null, null);
        //</editor-fold>

        $this->service->initialize();

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
     */
    public function testAssertInitialized(string $method, ...$args)
    {
        $this->expectException(\LogicException::class);
        $this->service->{$method}(...$args);
    }


    public function testGetAvailableRoles()
    {
        $this->authz->expects($this->once())->method('getAvailableRoles')
            ->willReturn(['user', 'manager', 'admin']);

        $this->assertEquals(['user', 'manager', 'admin'], $this->service->getAvailableRoles());
    }

    public function testIs()
    {
        $this->authz->expects($this->once())->method('is')
            ->with('foo')
            ->willReturn(true);

        $this->setPrivateProperty($this->service, 'initialized', true);

        $this->assertTrue($this->service->is('foo'));
    }

    public function testUser()
    {
        $user = $this->createMock(User::class);
        $this->authz->expects($this->once())->method('user')->willReturn($user);

        $this->setPrivateProperty($this->service, 'initialized', true);

        $this->assertSame($user, $this->service->user());
    }

    public function testContext()
    {
        $context = $this->createMock(Context::class);
        $this->authz->expects($this->once())->method('context')->willReturn($context);

        $this->setPrivateProperty($this->service, 'initialized', true);

        $this->assertSame($context, $this->service->context());
    }


    /**
     * @return Authz&MockObject
     */
    protected function expectSetAuthzUser(?User $user, ?Context $context = null)
    {
        $newAuthz = $this->createMock(Authz::class);

        $this->authz->expects($this->once())->method('forUser')
            ->with($this->identicalTo($user))
            ->willReturn($newAuthz);

        $newAuthz->expects($this->any())->method('user')
            ->willReturn($user);
        $newAuthz->expects($this->any())->method('context')
            ->willReturn($context);

        return $newAuthz;
    }

    /**
     * @return Authz&MockObject
     */
    protected function expectSetAuthzContext(?User $user, ?Context $context)
    {
        $newAuthz = $this->createMock(Authz::class);

        $this->authz->expects($this->once())->method('inContextOf')
            ->with($this->identicalTo($context))
            ->willReturn($newAuthz);

        $newAuthz->expects($this->any())->method('user')
            ->willReturn($user);
        $newAuthz->expects($this->any())->method('context')
            ->willReturn($context);

        return $newAuthz;
    }

    public function testLoginAs()
    {
        //<editor-fold desc="[prepare mocks]">
        $user = $this->createConfiguredMock(User::class, ['getId' => 42, 'getAuthChecksum' => 'abc']);

        $this->dispatcher->expects($this->once())->method('dispatch')
            ->with($this->callback(function ($event) use ($user) {
                $this->assertInstanceOf(Event\Login::class, $event);

                /** @var Event\Login $event */
                $this->assertSame($user, $event->getUser());
                $this->assertSame($this->service, $event->getEmitter());
                return true;
            }))
            ->willReturnArgument(0);

        $this->authz->expects($this->any())->method('user')->willReturn(null);
        $this->expectSetAuthzUser($user);

        $this->session->expects($this->once())->method('persist')
            ->with(42, null, 'abc');

        $this->setPrivateProperty($this->service, 'initialized', true);
        //</editor-fold>

        $this->service->loginAs($user);
    }

    public function testCancelLogin()
    {
        $user = $this->createConfiguredMock(User::class, ['getId' => 42, 'getAuthChecksum' => 'abc']);

        $this->dispatcher->expects($this->once())->method('dispatch')
            ->with($this->callback(function (Event\Login $event) {
                $event->cancel('no good');
                return true;
            }))
            ->willReturnArgument(0);

        //<editor-fold desc="[prepare mocks]">
        $this->authz->expects($this->any())->method('user')->willReturn(null);
        $this->authz->expects($this->never())->method('forUser');
        $this->authz->expects($this->never())->method('inContextOf');
        $this->session->expects($this->never())->method('persist');

        $this->expectException(LoginException::class);
        $this->expectExceptionMessage('no good');
        $this->expectExceptionCode(LoginException::CANCELLED);

        $this->setPrivateProperty($this->service, 'initialized', true);
        //</editor-fold>

        $this->service->loginAs($user);
    }

    public function testLoginAsTwice()
    {
        $user = $this->createMock(User::class);

        //<editor-fold desc="[prepare mocks]">
        $this->authz->expects($this->any())->method('user')->willReturn($user);

        $this->expectException(\LogicException::class);

        $this->setPrivateProperty($this->service, 'initialized', true);
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
        $user->expects($this->any())->method('getId')->willReturn(42);
        $user->expects($this->any())->method('getAuthChecksum')->willReturn('xyz');

        $this->dispatcher->expects($this->once())->method('dispatch')
            ->with($this->callback(function ($event) use ($user) {
                $this->assertInstanceOf(Event\Login::class, $event);

                /** @var Event\Login $event */
                $this->assertSame($user, $event->getUser());
                $this->assertSame($this->service, $event->getEmitter());
                return true;
            }))
            ->willReturnArgument(0);

        $this->authz->expects($this->any())->method('user')->willReturn(null);
        $this->expectSetAuthzUser($user);

        $this->session->expects($this->once())->method('persist')
            ->with(42, null, 'xyz');

        $this->setPrivateProperty($this->service, 'initialized', true);
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

        $this->authz->expects($this->any())->method('user')->willReturn(null);
        $this->authz->expects($this->never())->method('forUser');
        $this->authz->expects($this->never())->method('inContextOf');
        $this->session->expects($this->never())->method('persist');

        $this->expectException(LoginException::class);
        $this->expectExceptionMessage('Invalid credentials');
        $this->expectExceptionCode(LoginException::INVALID_CREDENTIALS);

        $this->setPrivateProperty($this->service, 'initialized', true);
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
        $user->expects($this->any())->method('getId')->willReturn(42);
        $user->expects($this->any())->method('getAuthChecksum')->willReturn('abc');

        $this->storage->expects($this->once())->method('fetchUserByUsername')
            ->with('john')
            ->willReturn($user);

        $this->dispatcher->expects($this->never())->method('dispatch');

        $this->authz->expects($this->any())->method('user')->willReturn(null);
        $this->authz->expects($this->never())->method('forUser');
        $this->authz->expects($this->never())->method('inContextOf');
        $this->session->expects($this->never())->method('persist');

        $this->setPrivateProperty($this->service, 'initialized', true);
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
        $this->authz->expects($this->any())->method('user')->willReturn($user);

        $this->setPrivateProperty($this->service, 'initialized', true);
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
                $this->assertSame($user, $event->getUser());
                $this->assertSame($this->service, $event->getEmitter());
                return true;
            }))
            ->willReturnArgument(0);

        $this->authz->expects($this->any())->method('user')->willReturn($user);
        $this->session->expects($this->once())->method('clear');

        $this->setPrivateProperty($this->service, 'initialized', true);
        //</editor-fold>

        $newAuthz = $this->expectInitAuthz(null, null);

        $this->service->logout();

        $this->assertSame($newAuthz, $this->service->authz());
    }

    public function testLogoutTwice()
    {
        $this->setPrivateProperty($this->service, 'initialized', true);

        $this->authz->expects($this->any())->method('user')->willReturn(null);
        $this->authz->expects($this->never())->method('forUser');
        $this->authz->expects($this->never())->method('inContextOf');
        $this->session->expects($this->never())->method('persist');

        $this->service->logout();
    }

    public function testSetContext()
    {
        $user = $this->createConfiguredMock(User::class, ['getId' => 42, 'getAuthChecksum' => 'abc']);
        $context = $this->createConfiguredMock(Context::class, ['getId' => 'foo']);

        //<editor-fold desc="[prepare mocks]">
        $this->authz->expects($this->any())->method('user')->willReturn($user);

        $this->session->expects($this->once())->method('persist')
            ->with(42, 'foo', 'abc');

        $this->setPrivateProperty($this->service, 'initialized', true);
        //</editor-fold>

        $newAuthz = $this->expectSetAuthzContext($user, $context);

        $this->service->setContext($context);

        $this->assertSame($newAuthz, $this->service->authz());
    }

    public function testClearContext()
    {
        $user = $this->createConfiguredMock(User::class, ['getId' => 42, 'getAuthChecksum' => 'abc']);

        //<editor-fold desc="[prepare mocks]">
        $this->authz->expects($this->any())->method('user')->willReturn($user);

        $this->session->expects($this->once())->method('persist')
            ->with(42, null, 'abc');

        $this->setPrivateProperty($this->service, 'initialized', true);
        //</editor-fold>

        $newAuthz = $this->expectSetAuthzContext($user, null);

        $this->service->setContext(null);

        $this->assertSame($newAuthz, $this->service->authz());
    }

    public function testUpdateSession()
    {
        $user = $this->createConfiguredMock(User::class, ['getId' => 42, 'getAuthChecksum' => 'abc']);
        $context = $this->createConfiguredMock(Context::class, ['getId' => 'foo']);

        //<editor-fold desc="[prepare mocks]">
        $this->authz->expects($this->any())->method('user')->willReturn($user);
        $this->authz->expects($this->any())->method('context')->willReturn($context);

        $this->session->expects($this->once())->method('persist')
            ->with(42, 'foo', 'abc');

        $this->setPrivateProperty($this->service, 'initialized', true);
        //</editor-fold>

        $this->service->updateSession();
    }


    public function testForUser()
    {
        $user = $this->createMock(User::class);
        $newAuthz = $this->createMock(Authz::class);

        $this->authz->expects($this->once())->method('forUser')
            ->with($user)
            ->willReturn($newAuthz);

        $this->setPrivateProperty($this->service, 'initialized', true);

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

        $this->setPrivateProperty($this->service, 'initialized', true);

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
