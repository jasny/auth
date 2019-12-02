<?php

declare(strict_types=1);

namespace Jasny\Auth\Authz;

use Improved\IteratorPipeline\Pipeline;
use Jasny\Auth\AuthzInterface;

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
class Groups implements AuthzInterface
{
    use StateTrait;

    /** @var array<string,string[]> */
    protected array $groups;


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
     * Expand groups to include all roles they supersede.
     *
     * @param string                 $role
     * @param array<string,string[]> $groups
     * @param string[]               $expanded  Accumulator
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
     * Check if the current user is logged in and has specified role.
     */
    public function is(string $role): bool
    {
        if (!isset($this->groups[$role])) {
            trigger_error("Unknown authz role '$role'", E_USER_WARNING); // Catch typos
            return false;
        }

        return in_array($role, $this->getUserRoles(), true);
    }

    /**
     * Get the (expanded) roles of the current user.
     *
     * @return string[]
     */
    protected function getUserRoles(): array
    {
        if ($this->user === null) {
            return [];
        }

        $role = $this->user->getRole($this->context);
        $roles = is_array($role) ? $role : [$role];

        return Pipeline::with($roles)
            ->map(fn($role) => $this->groups[$role] ?? [])
            ->flatten()
            ->unique()
            ->toArray();
    }
}
