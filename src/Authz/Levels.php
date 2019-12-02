<?php

declare(strict_types=1);

namespace Jasny\Auth\Authz;

use Improved as i;
use Improved\IteratorPipeline\Pipeline;
use Jasny\Auth\AuthzInterface;

/**
 * Authorize by access level.
 * @immutable
 *
 * <code>
 *   $authz = new Authz\Levels([
 *     'user' => 1,
 *     'moderator' => 100,
 *     'admin' => 1000
 *   ]);
 *
 *   $auth = new Auth($authz);
 * </code>
 */
class Levels implements AuthzInterface
{
    use StateTrait;

    /** @var array<string,int> */
    protected array $levels;

    /**
     * AuthzByLevel constructor.
     *
     * @param array<string,int> $levels
     */
    public function __construct(array $levels)
    {
        $this->levels = $levels;
    }

    /**
     * Get all available authorization roles (for the current context)
     *
     * @return string[]
     */
    public function getAvailableRoles(): array
    {
        return array_keys($this->levels);
    }

    /**
     * Check if the current user is logged in and has specified role.
     */
    public function is(string $role): bool
    {
        if (!isset($this->levels[$role])) {
            trigger_error("Unknown authz role '$role'", E_USER_WARNING); // Catch typos
            return false;
        }

        return $this->user !== null
            ? $this->getUserLevel() >= $this->levels[$role]
            : false;
    }

    /**
     * Get access level of the current user.
     *
     * @throws \DomainException for unknown level names
     */
    protected function getUserLevel(): int
    {
        if ($this->user === null) {
            throw new \BadMethodCallException('User not set'); // @codeCoverageIgnore
        }

        $uid = $this->user->getId();

        $role = i\type_check(
            $this->user->getRole($this->context),
            ['int', 'string'],
            new \UnexpectedValueException("For authz levels the role should be string|int, %s returned (uid:$uid)")
        );

        if (is_string($role) && !isset($this->levels[$role])) {
            throw new \DomainException("Authorization level '$role' isn't defined (uid:$uid)");
        }

        return is_string($role) ? $this->levels[$role] : (int)$role;
    }
}
