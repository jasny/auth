<?php

declare(strict_types=1);

namespace Jasny\Auth\Authz;

use Improved as i;
use Improved\IteratorPipeline\Pipeline;
use Jasny\Auth\AuthzInterface;
use Jasny\Auth\AuthzInterface as Authz;
use Jasny\Auth\ContextInterface as Context;
use Jasny\Auth\User\PartiallyLoggedIn;
use Jasny\Auth\UserInterface as User;

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
 *
 * Levels should be positive integers (greater than 0).
 */
class Levels implements AuthzInterface
{
    use StateTrait;

    /** @var array<string,int> */
    protected array $levels;

    /**
     * Cached user level. Service has an immutable state.
     */
    protected int $userLevel = 0;

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
     * Get a copy of the service with a modified property and recalculated
     * Returns $this if authz hasn't changed.
     *
     * @param string $property
     * @param string $value
     * @return static
     */
    protected function withProperty(string $property, $value): self
    {
        $clone = clone $this;
        $clone->{$property} = $value;

        $clone->calcUserLevel();

        $isSame = $clone->{$property} === $this->{$property} && $clone->userLevel === $this->userLevel;

        return $isSame ? $this : $clone;
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
     * Check if the current user is partially logged in.
     * Typically this means MFA verification is required.
     */
    public function isPartiallyLoggedIn(): bool
    {
        return $this->userLevel < 0;
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

        return $this->userLevel >= $this->levels[$role];
    }


    /**
     * Get a copy, recalculating the authz level of the user.
     * Returns $this if authz hasn't changed.
     *
     * @return static
     */
    public function recalc(): self
    {
        $clone = clone $this;
        $clone->calcUserLevel();

        return $clone->userLevel === $this->userLevel ? $this : $clone;
    }

    /**
     * Get access level of the current user.
     *
     * @throws \DomainException for unknown level names
     */
    private function calcUserLevel(): void
    {
        if ($this->user === null || $this->user instanceof PartiallyLoggedIn) {
            $this->userLevel = 0;
            return;
        }

        $this->userLevel = $this->getUserLevelFromRole();
    }

    /**
     * Get the user level from the auth role of the user.
     *
     * @throws \DomainException for unknown level names
     */
    private function getUserLevelFromRole(): int
    {
        $uid = $this->user->getAuthId();

        $role = i\type_check(
            $this->user->getAuthRole($this->context),
            ['int', 'string'],
            new \UnexpectedValueException("For authz levels the role should be string|int, %s returned (uid:$uid)")
        );

        if (is_string($role) && !isset($this->levels[$role])) {
            throw new \DomainException("Authorization level '$role' isn't defined (uid:$uid)");
        }

        return is_string($role) ? $this->levels[$role] : (int)$role;
    }
}
