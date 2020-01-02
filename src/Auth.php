<?php

declare(strict_types=1);

namespace Jasny\Auth;

use Jasny\Auth\AuthzInterface as Authz;
use Jasny\Auth\Confirmation\ConfirmationInterface as Confirmation;
use Jasny\Auth\Confirmation\NoConfirmation;
use Jasny\Auth\ContextInterface as Context;
use Jasny\Auth\Session\PhpSession;
use Jasny\Auth\Session\SessionInterface as Session;
use Jasny\Auth\StorageInterface as Storage;
use Jasny\Auth\UserInterface as User;
use Jasny\Immutable;
use Psr\EventDispatcher\EventDispatcherInterface as EventDispatcher;

/**
 * Authentication and authorization.
 */
class Auth implements Authz
{
    use Immutable\With;

    /**
     * Stateful authz service.
     * A new copy will be set if user is logged in or out, or if context changes.
     */
    protected Authz $authz;

    protected Session $session;
    protected Storage $storage;
    protected Confirmation $confirmation;
    protected EventDispatcher $dispatcher;

    /**
     * Auth constructor.
     */
    public function __construct(Authz $authz, Storage $storage, ?Confirmation $confirmation = null)
    {
        $this->authz = $authz;
        $this->storage = $storage;
        $this->confirmation = $confirmation ?? new NoConfirmation();

        // Set default services
        $this->dispatcher = self::dummyDispatcher();
    }

    /**
     * Get a copy with an event dispatcher.
     */
    public function withEventDispatcher(EventDispatcher $dispatcher): self
    {
        return $this->withProperty('dispatcher', $dispatcher);
    }


    /**
     * Initialize the service using session information.
     */
    public function initialize(?Session $session = null): void
    {
        if ($this->isInitialized()) {
            throw new \LogicException("Auth service is already initialized");
        }

        $this->session = $session ?? new PhpSession();

        ['user' => $user, 'context' => $context] = $this->getInfoFromSession();

        $this->authz = $this->authz->forUser($user)->inContextOf($context);
    }

    /**
     * Get user and context from session, loading objects from storage.
     *
     * @return array{user:User|null,context:Context|null}
     */
    protected function getInfoFromSession()
    {
        ['uid' => $uid, 'context' => $cid, 'checksum' => $checksum] = $this->session->getInfo();

        $user = $uid !== null
            ? ($uid instanceof User ? $uid : $this->storage->fetchUserById($uid))
            : null;

        if ($user !== null && $user->getAuthChecksum() !== $checksum) {
            return ['user' => null, 'context' => null];
        }

        $context = $cid !== null
            ? ($cid instanceof Context ? $cid : $this->storage->fetchContext($cid))
            : ($user !== null ? $this->storage->getContextForUser($user) : null);

        return ['user' => $user, 'context' => $context];
    }

    /**
     * Is the service is initialized?
     */
    public function isInitialized(): bool
    {
        return isset($this->session);
    }

    /**
     * Throw an exception if the service hasn't been initialized yet.
     *
     * @throws \LogicException
     */
    protected function assertInitialized(): void
    {
        if (!$this->isInitialized()) {
            throw new \LogicException("Auth needs to be initialized before use");
        }
    }


    /**
     * Get all available authorization roles (for the current context).
     *
     * @return string[]
     */
    final public function getAvailableRoles(): array
    {
        return $this->authz->getAvailableRoles();
    }


    /**
     * Check if the current user is logged in.
     */
    final public function isLoggedIn(): bool
    {
        $this->assertInitialized();

        return $this->authz->isLoggedIn();
    }

    /**
     * Check if the current user is logged in and has specified role.
     *
     * <code>
     *   if (!$auth->is('manager')) {
     *     http_response_code(403); // Forbidden
     *     echo "You are not allowed to view this page";
     *     exit();
     *   }
     * </code>
     */
    final public function is(string $role): bool
    {
        $this->assertInitialized();

        return $this->authz->is($role);
    }

    /**
     * Get current authenticated user.
     *
     * @throws AuthException if no user is logged in.
     */
    final public function user(): User
    {
        $this->assertInitialized();

        return $this->authz->user();
    }

    /**
     * Get the current context.
     */
    final public function context(): ?Context
    {
        $this->assertInitialized();

        return $this->authz->context();
    }


    /**
     * Set the current user.
     *
     * @throws LoginException
     */
    public function loginAs(User $user): void
    {
        $this->assertInitialized();

        if ($this->authz->isLoggedIn()) {
            throw new \LogicException("Already logged in");
        }

        $this->loginUser($user);
    }

    /**
     * Login with username and password.
     *
     * @throws LoginException
     */
    public function login(string $username, string $password): void
    {
        $this->assertInitialized();

        if ($this->authz->isLoggedIn()) {
            throw new \LogicException("Already logged in");
        }

        $user = $this->storage->fetchUserByUsername($username);

        if ($user === null || !$user->verifyPassword($password)) {
            throw new LoginException('Invalid credentials', LoginException::INVALID_CREDENTIALS);
        }

        $this->loginUser($user);
    }

    /**
     * Set the current user and dispatch login event.
     *
     * @throws LoginException
     */
    private function loginUser(User $user): void
    {
        $event = new Event\Login($this, $user);
        $this->dispatcher->dispatch($event);

        if ($event->isCancelled()) {
            throw new LoginException($event->getCancellationReason(), LoginException::CANCELLED);
        }

        // Beware; the `authz` property may have been changed via the login event.
        $this->authz = $this->authz->forUser($user);

        if ($this->authz->context() === null) {
            $context = $this->storage->getContextForUser($user);
            $this->authz = $this->authz->inContextOf($context);
        }

        $this->updateSession();
    }

    /**
     * Logout current user.
     */
    public function logout(): void
    {
        $this->assertInitialized();

        if (!$this->authz()->isLoggedIn()) {
            return;
        }

        $user = $this->authz->user();

        $this->authz = $this->authz->forUser(null)->inContextOf(null);
        $this->updateSession();

        $this->dispatcher->dispatch(new Event\Logout($this, $user));
    }

    /**
     * Set the current context.
     */
    public function setContext(?Context $context): void
    {
        $this->assertInitialized();

        $this->authz = $this->authz->inContextOf($context);
        $this->updateSession();
    }

    /**
     * Recalculate authz roles for current user and context.
     * Store the current auth information in the session.
     *
     * @return $this
     */
    public function recalc(): self
    {
        $this->authz = $this->authz->recalc();
        $this->updateSession();

        return $this;
    }

    /**
     * Store the current auth information in the session.
     */
    protected function updateSession(): void
    {
        if (!$this->authz->isLoggedIn()) {
            $this->session->clear();
            return;
        }

        $user = $this->authz->user();
        $context = $this->authz->context();

        $uid = $user->getAuthId();
        $cid = $context !== null ? $context->getAuthId() : null;
        $checksum = $user->getAuthChecksum();

        $this->session->persist($uid, $cid, $checksum);
    }


    /**
     * Return read-only service for authorization of the current user and context.
     */
    public function authz(): Authz
    {
        return $this->authz;
    }

    /**
     * Return read-only service for authorization of the specified user.
     */
    public function forUser(?User $user): Authz
    {
        return $this->authz->forUser($user);
    }

    /**
     * Get an authz service for the given context.
     */
    public function inContextOf(?Context $context): Authz
    {
        return $this->authz->inContextOf($context);
    }


    /**
     * Get service to create or validate confirmation token.
     */
    public function confirm(string $subject): Confirmation
    {
        return $this->confirmation->withStorage($this->storage)->withSubject($subject);
    }


    /**
     * Create an event dispatcher as null object.
     * @codeCoverageIgnore
     */
    private static function dummyDispatcher(): EventDispatcher
    {
        return new class () implements EventDispatcher {
            /** @inheritDoc */
            public function dispatch(object $event): object
            {
                return $event;
            }
        };
    }
}
