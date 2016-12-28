<?php

namespace Jasny\Auth;

use Jasny\Auth;
use Jasny\Authz;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;

/**
 * Access control middleware
 */
class Middleware
{
    /**
     * @var Auth|Authz
     **/
    protected $auth;

    /**
     * Function to get the required role from the request.
     * @var callable
     */
    protected $getRequiredRole;
    
    /**
     * Class constructor
     *
     * @param Authz    $auth
     * @param callable $getRequiredRole
     */
    public function __construct(Authz $auth, $getRequiredRole)
    {
        $this->auth = $auth;
        
        if (!is_callable($getRequiredRole)) {
            throw new \InvalidArgumentException("'getRequiredRole' should be callable");
        }
        
        $this->getRequiredRole = $getRequiredRole;
    }

    /**
     * Check if the current user has one of the roles
     * 
     * @param array $roles
     * @return
     */
    protected function hasRole(array $roles)
    {
        $ret = false;
        
        foreach ($roles as $role) {
            $ret = $ret || $this->auth->is($role);
        }
        
        return $ret;
    }
    
    /**
     * Respond with forbidden (or unauthorized)
     * 
     * @param ServerRequestInterface $request
     * @param ResponseInterface      $response
     * @return ResponseInterface
     */
    protected function forbidden(ServerRequestInterface $request, ResponseInterface $response)
    {
        $unauthorized = $this->auth instanceof Auth && $this->auth->user() === null;
        
        $forbiddenResponse = $response->withStatus($unauthorized ? 401 : 403);
        $forbiddenResponse->getBody()->write('Access denied');
        
        return $forbiddenResponse;
    }
    
    /**
     * Run middleware action
     *
     * @param ServerRequestInterface $request
     * @param ResponseInterface      $response
     * @param callable               $next
     * @return ResponseInterface
     */
    public function __invoke(ServerRequestInterface $request, ResponseInterface $response, $next)
    {
        if (!is_callable($next)) {
            throw new \InvalidArgumentException("'next' should be callable");
        }

        $requiredRole = call_user_func($this->getRequiredRole, $request);
        
        if (!empty($requiredRole) && !$this->hasRole((array)$requiredRole)) {
            return $this->forbidden($request, $response);
        }

        return $next($request, $response);
    }
}
