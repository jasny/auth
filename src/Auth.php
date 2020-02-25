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
use Jasny\Auth\User\PartiallyLoggedIn;
use Jasny\Auth\UserInterface as User;
use Jasny\Immutable;
use Psr\EventDispatcher\EventDispatcherInterface as EventDispatcher;
use Psr\Log\LoggerInterface as Logger;
use Psr\Log\NullLogger;

/**
 * Authentication and authorization.
 */
class Auth implements Authz
{
    use Immutable\With;
    use Immutable\NoDynamicProperties;

    /**
     * Stateful authz service.
     * A new copy will be set if user is logged in or out, or if context changes.
     */
    protected Authz $authz;

    /**
     * Time when logged in.
     */
    protected ?\DateTimeInterface $timestamp = null;

    protected Session $session;
    protected Storage $storage;
    protected Confirmation $confirmation;

    protected EventDispatcher $dispatcher;
    protected Logger $logger;

    /** Allow service to be re-initialized */
    protected bool $forMultipleRequests = false;

    /** @var \Closure&callable(User $user, string $code):bool */
    protected \Closure $verifyMFA;

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
        $this->logger = new NullLogger();
        $this->verifyMFA = fn() => false;
    }

    /**
     * Get a copy of the service that allows reinitializing it.
     *
     * @return static
     */
    public function forMultipleRequests(): self
    {
        return $this->withProperty('forMultipleRequests', true);
    }

    /**
     * Get a copy with an event dispatcher.
     */
    public function withEventDispatcher(EventDispatcher $dispatcher): self
    {
        return $this->withProperty('dispatcher', $dispatcher);
    }

    /**
     * Get a copy with a logger.
     */
    public function withLogger(Logger $logger): self
    {
        return $this->withProperty('logger', $logger);
    }

    /**
     * Get the logger used for this service.
     */
    public function getLogger(): Logger
    {
        return $this->logger;
    }

    /**
     * Get a copy of the service with Multi Factor Authentication (MFA) support.
     *
     * @param callable $verify  Callback to verify MFA.
     * @return static
     */
    public function withMFA(callable $verify): self
    {
        return $this->withProperty('verifyMFA', \Closure::fromCallable($verify));
    }


    /**
     * Initialize the service using session information.
     */
    public function initialize(?Session $session = null): void
    {
        if ($this->isInitialized()) {
            if (!$this->forMultipleRequests) {
                throw new \LogicException("Auth service is already initialized");
            }

            $this->authz = $this->authz()->forUser(null)->inContextOf(null);
        }

        $this->session = $session ?? new PhpSession();
        ['user' => $user, 'context' => $context, 'timestamp' => $this->timestamp] = $this->getInfoFromSession();

        $this->authz = $this->authz->forUser($user)->inContextOf($context);
    }

    /**
     * Get user and context from session, loading objects from storage.
     *
     * @return array{user:User|null,context:Context|null,timestamp:\DateTimeInterface|null}
     */
    protected function getInfoFromSession()
    {
        $partial = false;

        $info = $this->session->getInfo();
        ['user' => $uid, 'context' => $cid, 'checksum' => $checksum, 'timestamp' => $timestamp] = $info;

        if ($uid === null || $uid instanceof User) {
            $user = $uid;
        } else {
            if (substr($uid, 0, 9) === '#partial:') {
                $partial = true;
                $uid = substr($uid, 9);
            }
            $user = $this->storage->fetchUserById($uid);
        }

        if ($user === null) {
            return ['user' => null, 'context' => null, 'timestamp' => null];
        }

        if ($user->getAuthChecksum() !== (string)$checksum) {
            $authId = $user->getAuthId();
            $this->logger->notice("Ignoring auth info from session: invalid checksum", ['user' => $authId]);

            return ['user' => null, 'context' => null, 'timestamp' => null];
        }

        $context = $cid !== null
            ? ($cid instanceof Context ? $cid : $this->storage->fetchContext($cid))
            : (!$partial ? $this->storage->getContextForUser($user) : null);

        if ($partial) {
            $user = new PartiallyLoggedIn($user);
        }

        return ['user' => $user, 'context' => $context, 'timestamp' => $timestamp];
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
     * Check if the current user is partially logged in.
     * Typically this means MFA verification is required.
     */
    final public function isPartiallyLoggedIn(): bool
    {
        $this->assertInitialized();
        return $this->authz->isPartiallyLoggedIn();
    }

    /**
     * Check if the current user is not logged in or partially logged in.
     */
    final public function isLoggedOut(): bool
    {
        $this->assertInitialized();
        return $this->authz->isLoggedOut();
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
     * Get the login timestamp.
     */
    public function time(): ?\DateTimeInterface
    {
        return $this->timestamp;
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
            $this->logger->debug("Login failed: invalid credentials", ['username' => $username]);
            throw new LoginException('Invalid credentials', LoginException::INVALID_CREDENTIALS);
        }

        $this->loginUser($user);
    }

    /**
     * Set the current user and dispatch login event.
     *
     * @throws LoginException
     * @noinspection PhpDocMissingThrowsInspection
     */
    private function loginUser(User $user): void
    {
        if ($user->requiresMFA()) {
            $this->partialLoginUser($user);
            return;
        }

        $event = new Event\Login($this, $user);
        $this->dispatcher->dispatch($event);

        if ($event->isCancelled()) {
            $this->logger->info("Login failed: " . $event->getCancellationReason(), ['user' => $user->getAuthId()]);
            throw new LoginException($event->getCancellationReason(), LoginException::CANCELLED);
        }

        // Beware; the `authz` property may have been changed via the login event.
        $this->authz = $this->authz->forUser($user);

        if ($this->authz->context() === null) {
            $context = $this->storage->getContextForUser($user);
            $this->authz = $this->authz->inContextOf($context);
        }

        $this->timestamp = new \DateTimeImmutable();
        $this->updateSession();

        $this->logger->info("Login successful", ['user' => $user->getAuthId()]);
    }

    /**
     * Set the current user and dispatch login event.
     *
     * @throws LoginException
     * @noinspection PhpDocMissingThrowsInspection
     */
    private function partialLoginUser(User $user): void
    {
        $event = new Event\PartialLogin($this, $user);
        $this->dispatcher->dispatch($event);

        if ($event->isCancelled()) {
            $this->logger->info("Login failed: " . $event->getCancellationReason(), ['user' => $user->getAuthId()]);
            throw new LoginException($event->getCancellationReason(), LoginException::CANCELLED);
        }

        // Beware; the `authz` property may have been changed via the partial login event.
        $this->authz = $this->authz->forUser(new PartiallyLoggedIn($user));

        $this->timestamp = new \DateTimeImmutable();
        $this->updateSession();

        $this->logger->info("Partial login", ['user' => $user->getAuthId()]);
    }

    /**
     * MFA verification.
     */
    public function mfa(string $code): void
    {
        $this->assertInitialized();

        if ($this->isLoggedOut()) {
            throw new \RuntimeException("Unable to perform MFA verification: No user (partially) logged in.");
        }

        $user = $this->user();

        $verified = ($this->verifyMFA)($user, $code);

        if (!$verified) {
            $this->logger->debug("Login failed: invalid MFA", ['user' => $user->getAuthId()]);
            throw new LoginException('Invalid MFA', LoginException::INVALID_CREDENTIALS);
        }

        if ($user instanceof PartiallyLoggedIn) {
            $this->loginAs($user->getUser());
        }
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

        $this->logger->debug("Logout", ['user' => $user->getAuthId()]);
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
        if ($this->authz->isLoggedOut()) {
            $this->timestamp = null;
            $this->session->clear();

            return;
        }

        $user = $this->authz->user();
        $context = $this->authz->context();

        $uid = $user->getAuthId();
        $cid = $context !== null ? $context->getAuthId() : null;
        $checksum = $user->getAuthChecksum();

        $this->session->persist($uid, $cid, $checksum, $this->timestamp);
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
        return $this->confirmation
            ->withStorage($this->storage)
            ->withLogger($this->logger)
            ->withSubject($subject);
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
