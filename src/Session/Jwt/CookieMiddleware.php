<?php

declare(strict_types=1);

namespace Jasny\Auth\Session\Jwt;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as ServerRequest;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;

/**
 * Middleware to get JWT cookie from a PSR-7 request and set JWT cookie in the response.
 */
class CookieMiddleware implements MiddlewareInterface
{
    protected string $name;

    /**
     * @var array<string,mixed>
     */
    protected array $options = [
        'path' => '',
        'domain' => '',
        'secure' => false,
        'httponly' => true,
        'samesite' => '',
    ];

    /**
     * Cookies constructor.
     *
     * @param string              $name
     * @param array<string,mixed> $options
     */
    public function __construct(string $name = 'jwt', array $options = [])
    {
        $this->name = $name;
        $this->options = array_change_key_case($options, CASE_LOWER) + $this->options;
    }

    /**
     * @inheritDoc
     */
    public function process(ServerRequest $request, RequestHandler $handler): Response
    {
        return $this->processRequest($request, [$handler, 'handle']);
    }

    /**
     * Get a callback that can be used as double pass middleware.
     *
     * @return callable
     */
    public function asDoublePass(): callable
    {
        return function (ServerRequest $request, Response $response, callable $next): Response {
            return $this->processRequest($request, fn(ServerRequest $request) => $next($request, $response));
        };
    }

    /**
     * Process the PSR-7 request and set the JWT cookie for the response.
     *
     * @param ServerRequest                    $request
     * @param callable(ServerRequest):Response $handle
     * @return Response
     */
    protected function processRequest(ServerRequest $request, callable $handle): Response
    {
        $cookieValue = $request->getCookieParams()[$this->name] ?? null;
        $cookie = new CookieValue($cookieValue);

        /** @var Response $response */
        $response = $handle($request->withAttribute('jwt_cookie', $cookie));

        // Cookie value has changed => jwt is set (or cleared)
        if ($cookie->get() !== $cookieValue) {
            $header = $this->getSetCookieHeader($cookie->get() ?? '', $cookie->getExpire());
            $response = $response->withAddedHeader('Set-Cookie', $header);
        }

        return $response;
    }

    /**
     * Get the header string for `Set-Cookie`.
     */
    protected function getSetCookieHeader(string $value, int $expire): string
    {
        $header = $this->name . '=' . urlencode($value);

        if ($expire !== 0) {
            $header .= '; Expires=' . gmdate('D, d M Y H:i:s T', $expire);
        }

        foreach (['Path', 'Domain', 'SameSite'] as $opt) {
            $header .= (string)$this->options[strtolower($opt)] !== ''
                ? "; {$opt}=" . $this->options[strtolower($opt)]
                : '';
        }

        foreach (['Secure', 'HttpOnly'] as $opt) {
            $header .= (string)$this->options[strtolower($opt)] !== ''
                ? "; {$opt}"
                : '';
        }

        return $header;
    }
}
