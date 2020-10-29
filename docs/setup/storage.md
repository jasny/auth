---
layout: default
title: Storage
parent: Setup
nav_order: 2
---

# Storage

The `Storage` service is not provided, you'll need to create a service that can fetch a user from the database.

```php
use Jasny\Auth;

class AuthStorage implements Auth\StorageInterface
{
    /**
     * Fetch a user by ID
     */
    public function fetchUserById(string $id): ?Auth\UserInterface
    {
        // Database action that fetches a User object
    }

    /**
     * Fetch a user by username
     */
    public function fetchUserByUsername(string $username): ?Auth\UserInterface
    {
        // Database action that fetches a User object
    }
    
    /**
     * Fetch the context by ID.
     */
    public function fetchContext(string $id) : ?Auth\ContextInterface
    {
        // Database action that fetches a context (or return null)
    }
    
    /**
     * Get the default context of the user.  
     */
    public function getContextForUser(Auth\UserInterface $user) : ?Auth\ContextInterface
    {
        return null;
    }
}
```
