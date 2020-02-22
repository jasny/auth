<?php

declare(strict_types=1);

namespace Jasny\Auth\Authz;

use Improved\IteratorPipeline\Pipeline;
use Jasny\Auth\AuthzInterface as Authz;
use Jasny\Auth\ContextInterface as Context;
use Jasny\Auth\UserInterface as User;

/**
 * Authorize by access group.
 * Can be used for ACL (Access Control List).
 * @immutable
 *
 * <code>
 *   $authz = new Authz\Groups([
 *     'user' => [],
 *     'accountant' => ['user'],
 *     'moderator' => ['user'],
 *     'developer' => ['user'],
 *     'admin' => ['moderator', 'developer']
 *   ]);
 *
 *   $auth = new Auth($authz);
 * </code>
 */
class Groups implements Authz
{
    use StateTrait;

    protected const PARTIAL = '#partial';

    /** @var array<string,array<string>> */
    protected array $groups;

    /**
     * Current authenticated user
     */
    protected ?User $user = null;

    /**
     * The authorization context. This could be an organization, where a user has specific roles per organization
     * rather than roles globally.
     */
    protected ?Context $context = null;

    /**
     * Cached user level. Service has an immutable state.
     * @var string[]
     */
    protected array $userRoles = [];

    /**
     * AuthzByGroup constructor.
     *
     * @param array<string,string[]> $groups
     */
    public function __construct(array $groups)
    {
        foreach ($groups as $group => &$roles) {
            $roles = $this->expand($group, $groups);
        }

        $this->groups = $groups;
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

        $clone->calcUserRoles();

        $isSame = $clone->{$property} === $this->{$property} && $clone->userRoles === $this->userRoles;

        return $isSame ? $this : $clone;
    }

    /**
     * Expand groups to include all roles they supersede.
     *
     * @param string                      $role
     * @param array<string,array<string>> $groups
     * @param string[]                    $expanded  Accumulator
     * @return string[]
     */
    protected function expand(string $role, array $groups, array &$expanded = []): array
    {
        $expanded[] = $role;

        // Ignore duplicates.
        $additionalRoles = array_diff($groups[$role], $expanded);

        // Remove current role from groups to prevent issues from cross-references.
        $groupsWithoutCurrent = array_diff_key($groups, [$role => null]);

        // Recursively expand the superseded roles.
        foreach ($additionalRoles as $additionalRole) {
            $this->expand($additionalRole, $groupsWithoutCurrent, $expanded);
        }

        return $expanded;
    }


    /**
     * Get all available authorization roles (for the current context).
     *
     * @return string[]
     */
    public function getAvailableRoles(): array
    {
        return array_keys($this->groups);
    }


    /**
     * Check if the current user is partially logged in.
     * Typically this means MFA verification is required.
     */
    public function isPartiallyLoggedIn(): bool
    {
        return in_array(self::PARTIAL, $this->userRoles, true);
    }

    /**
     * Check if the current user is logged in and has specified role.
     */
    public function is(string $role): bool
    {
        if (!isset($this->groups[$role])) {
            trigger_error("Unknown authz role '$role'", E_USER_WARNING); // Catch typos
            return false;
        }

        return in_array($role, $this->userRoles, true);
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
        $clone->calcUserRoles();

        return $clone->userRoles === $this->userRoles ? $this : $clone;
    }

    /**
     * Calculate the (expanded) roles of the current user.
     */
    protected function calcUserRoles(): void
    {
        if ($this->user === null) {
            $this->userRoles = [];
            return;
        }

        $role = $this->user->getAuthRole($this->context);
        $roles = is_array($role) ? $role : [$role];

        $this->userRoles = Pipeline::with($roles)
            ->map(fn($role) => $this->groups[$role] ?? [])
            ->flatten()
            ->unique()
            ->toArray();
    }
}
