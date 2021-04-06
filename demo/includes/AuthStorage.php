<?php

declare(strict_types=1);

use Jasny\Auth;
use Jasny\Auth\User\BasicUser;

/**
 * Authentication storage class.
 *
 * Normally users would be fetched from the database.
 * @see https://www.jasny.net/auth/setup/storage.html
 */
class AuthStorage implements Auth\StorageInterface
{
    /**
     * A list of users.
     * DO NOT COPY THIS; Use a database to store and fetch the users instead.
     */
    public const USERS = [
        [
            'id' => 1,
            'username' => 'jackie',
            'hashedPassword' => '$2y$10$lVUeiphXLAm4pz6l7lF9i.6IelAqRxV4gCBu8GBGhCpaRb6o0qzUO', // jackie123
            'role' => 1, // user
        ],
        [
            'id' => 2,
            'username' => 'john',
            'hashedPassword' => '$2y$10$RU85KDMhbh8pDhpvzL6C5.kD3qWpzXARZBzJ5oJ2mFoW7Ren.apC2', // john123
            'role' => 10, // admin
        ],
    ];

    /**
     * Fetch a user by ID.
     */
    public function fetchUserById(string $id): ?Auth\UserInterface
    {
        foreach (self::USERS as $user) {
            if ((string)$user['id'] === $id) {
                return BasicUser::fromData($user);
            }
        }

        return null;
    }

    /**
     * Fetch a user by username
     */
    public function fetchUserByUsername(string $username): ?Auth\UserInterface
    {
        foreach (self::USERS as $user) {
            if ($user['username'] === $username) {
                return BasicUser::fromData($user);
            }
        }

        return null;
    }

    /**
     * Fetch the context by ID.
     */
    public function fetchContext(string $id) : ?Auth\ContextInterface
    {
        // Return null if this application doesn't work with teams or organizations for auth.
        return null;
    }

    /**
     * Get the default context of the user.
     */
    public function getContextForUser(Auth\UserInterface $user) : ?Auth\ContextInterface
    {
        return null;
    }
}