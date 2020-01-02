<?php

declare(strict_types=1);

namespace Jasny\Auth;

use Improved as i;
use Improved\IteratorPipeline\Pipeline;
use Jasny\Auth\AuthzInterface as Authz;
use Jasny\Auth\Session\SessionInterface;
use Psr\Http\Message\ServerRequestInterface as ServerRequest;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ResponseFactoryInterface as ResponseFactory;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;
use Psr\Http\Server\MiddlewareInterface;

/**
 * Middleware for access control.
 */
class AuthMiddleware implements MiddlewareInterface
{
    protected Authz $auth;
    protected ?ResponseFactory $responseFactory = null;

    /**
     * @var null|\Closure(ServerRequest $request):SessionInterface
     */
    protected ?\Closure $getSession;

    /**
     * @var \Closure(ServerRequest $request):mixed
     * Function to get the required role from the request.
     */
    protected \Closure $getRequiredRole;

    /**
     * Class constructor
     *
     * @param Authz                                  $auth
     * @param callable(ServerRequest $request):mixed $getRequiredRole
     * @param ResponseFactory|null                   $responseFactory
     */
    public function __construct(Authz $auth, callable $getRequiredRole, ?ResponseFactory $responseFactory = null)
    {
        $this->auth = $auth;
        $this->responseFactory = $responseFactory;
        $this->getRequiredRole = \Closure::fromCallable($getRequiredRole);
    }

    /**
     * Get a copy of this middleware with a different session service.
     *
     * @param callable(ServerRequest $request):SessionInterface $getSession
     * @return static
     */
    public function withSession(callable $getSession): self
    {
        $copy = clone $this;
        $copy->getSession = \Closure::fromCallable($getSession);

        return $copy;
    }

    /**
     * Process an incoming server request (PSR-15).
     *
     * @param ServerRequest  $request
     * @param RequestHandler $handler
     * @return Response
     */
    public function process(ServerRequest $request, RequestHandler $handler): Response
    {
        $this->initialize($request);

        if (!$this->isAllowed($request)) {
            return $this->forbidden($request);
        }

        return $handler->handle($request);
    }

    /**
     * Get a callback that can be used as double pass middleware.
     *
     * @return callable
     */
    public function asDoublePass(): callable
    {
        return function (ServerRequest $request, Response $response, callable $next): Response {
            $this->initialize($request);

            if (!$this->isAllowed($request)) {
                return $this->forbidden($request, $response);
            }

            return $next($request, $response);
        };
    }

    /**
     * Initialize the auth service.
     */
    protected function initialize(ServerRequest $request): void
    {
        if (!($this->auth instanceof Auth) || $this->auth->isInitialized()) {
            if (isset($this->getSession)) {
                throw new \LogicException("Session couldn't be used; auth already initialized");
            }
            return;
        }

        $session = $this->getSession($request);
        $this->auth->initialize($session);
    }

    /**
     * Return a session service for the server request.
     */
    protected function getSession(ServerRequest $request): ?SessionInterface
    {
        if (!isset($this->getSession)) {
            return null;
        }

        return i\type_check(
            ($this->getSession)($request),
            SessionInterface::class,
            new \UnexpectedValueException()
        );
    }

    /**
     * Check if the request is allowed by the current user.
     */
    protected function isAllowed(ServerRequest $request): bool
    {
        $requiredRole = ($this->getRequiredRole)($request);

        if ($requiredRole === null) {
            return true;
        }

        if (is_bool($requiredRole)) {
            return $this->auth->isLoggedIn() === $requiredRole;
        }

        return Pipeline::with(is_array($requiredRole) ? $requiredRole : [$requiredRole])
            ->hasAny(fn($role) => $this->auth->is($role));
    }

    /**
     * Respond with forbidden (or unauthorized).
     */
    protected function forbidden(ServerRequest $request, ?Response $response = null): Response
    {
        $forbiddenResponse = $this->createResponse($this->auth->isLoggedIn() ? 403 : 401, $response)
            ->withProtocolVersion($request->getProtocolVersion());
        $forbiddenResponse->getBody()->write('Access denied');

        return $forbiddenResponse;
    }

    /**
     * Create a response using the response factory.
     *
     * @param int           $status            Response status
     * @param Response|null $originalResponse
     * @return Response
     */
    protected function createResponse(int $status, ?Response $originalResponse = null): Response
    {
        if ($this->responseFactory !== null) {
            return $this->responseFactory->createResponse($status);
        }

        if ($originalResponse !== null) {
            // There is no standard way to get an empty body without a factory. One of these methods may work.
            $body = clone $originalResponse->getBody();
            $body->rewind();

            return $originalResponse->withStatus($status)->withBody($body);
        }

        throw new \LogicException('Response factory not set');
    }
}
