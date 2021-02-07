---
layout: default
title: Storage
parent: Setup
nav_order: 2
---

# Storage

The `Storage` service is not provided, you'll need to create a service that can fetch a user from the database.

## PDO

In this example we fetch data from MySQL using PDO.

The `BasicUser` class is implements `UserInterface`. It only defines a few properties, and should only be used for the
`Auth` class. For more information see the [User setup](user.md) page.

```php
use Jasny\Auth;
use Jasny\Auth\User\BasicUser;

class AuthStorage implements Auth\StorageInterface
{
    protected \PDO $db;

    /**
     * Class constructor.
     */
    public function __construct(\PDO $db)
    {
        $this->db = $db;
    }

    /**
     * Fetch a user by ID
     */
    public function fetchUserById(string $id): ?Auth\UserInterface
    {
        $stmt = $this->db->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$id]);
        $data = $stmt->fetch(\PDO::FETCH_ASSOC);
        
        return $data !== null ? BasicUser::fromData($data) : null;
    }

    /**
     * Fetch a user by username
     */
    public function fetchUserByUsername(string $username): ?Auth\UserInterface
    {
        $stmt = $this->db->prepare("SELECT * FROM users WHERE username = ?"); // could use email instead of username
        $stmt->execute([$username]);
        $data = $stmt->fetch(\PDO::FETCH_ASSOC);
        
        return $data !== null ? BasicUser::fromData($data) : null;
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
```

## Doctrine

When using an Object Relation Model (ORM) library, like Doctrine, will create objects from data in the database. These
objects can be used by the Auth library.

```php
use Jasny\Auth;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;

class AuthStorage implements Auth\StorageInterface
{
    protected ServiceEntityRepository $users;
    protected ServiceEntityRepository $teams;

    /**
     * Class constructor.
     */
    public function __construct(ServiceEntityRepository $users, ServiceEntityRepository $teams)
    {
        $this->users = $users;
        $this->teams = $teams;
    }

    /**
     * Fetch a user by ID
     */
    public function fetchUserById(string $id): ?Auth\UserInterface
    {
        return $this->users->find($id);
    }

    /**
     * Fetch a user by username
     */
    public function fetchUserByUsername(string $username): ?Auth\UserInterface
    {
        return $this->users->findOneBy(['username' => $username]); // could use email instead of username
    }
    
    /**
     * Fetch the context by ID.
     */
    public function fetchContext(string $id) : ?Auth\ContextInterface
    {
        $this->teams->find($id);
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

Make sure that the user entity class implements `Auth\UserInterface`. For more information see the
[User setup](user.md) page.

```php
namespace MyProject\Domain;

use Jasny\Auth;

class User implements Auth\UserInterface
{
    // ...
}
```