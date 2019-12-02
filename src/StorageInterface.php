<?php

declare(strict_types=1);

namespace Jasny\Auth;

use Jasny\Auth\UserInterface as User;
use Jasny\Auth\ContextInterface as Context;

/**
 * Interface to storage of persistent (user) data.
 */
interface StorageInterface
{
    /**
     * Fetch user from DB by id.
     *
     * @param string|int $id
     * @return User|null
     */
    public function fetchUserById($id): ?User;

    /**
     * Fetch user from DB by username.
     *
     * @param string $username
     * @return User|null
     */
    public function fetchUserByUsername(string $username): ?User;

    /**
     * Fetch context from DB by id.
     *
     * @param mixed $id
     * @return Context|null
     */
    public function fetchContext($id): ?Context;
}
