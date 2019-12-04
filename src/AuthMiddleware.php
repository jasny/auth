<?php

declare(strict_types=1);

namespace Jasny\Auth;

use Improved\IteratorPipeline\Pipeline;
use Jasny\Auth\AuthzInterface as Authz;
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

    /** Function to get the required role from the request. */
    protected \Closure $getRequiredRole;

    /**
     * Class constructor
     *
     * @param Authz    $auth
     * @param callable $getRequiredRole
     */
    public function __construct(Authz $auth, callable $getRequiredRole, ?ResponseFactory $responseFactory = null)
    {
        $this->auth = $auth;
        $this->responseFactory = $responseFactory;
        $this->getRequiredRole = \Closure::fromCallable($getRequiredRole);
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
        $this->initialize();

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
            $this->initialize();

            if (!$this->isAllowed($request)) {
                return $this->forbidden($request, $response);
            }

            return $next($request, $response);
        };
    }

    /**
     * Initialize the auth service.
     */
    protected function initialize(): void
    {
        if ($this->auth instanceof Auth && !$this->auth->isInitialized()) {
            $this->auth->initialize();
        }
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
            return ($this->auth->user() !== null) === $requiredRole;
        }

        return Pipeline::with(is_array($requiredRole) ? $requiredRole : [$requiredRole])
            ->hasAny(fn($role) => $this->auth->is($role));
    }

    /**
     * Respond with forbidden (or unauthorized).
     */
    protected function forbidden(ServerRequest $request, ?Response $response = null): Response
    {
        $unauthorized = $this->auth->user() === null;

        $forbiddenResponse = $this->createResponse($unauthorized ? 401 : 403, $response)
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
        } elseif ($originalResponse !== null) {
            return $originalResponse->withStatus($status)->withBody(clone $originalResponse->getBody());
            ;
        } else {
            throw new \LogicException('Response factory not set');
        }
    }
}
