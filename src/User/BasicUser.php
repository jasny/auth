<?php

declare(strict_types=1);

namespace Jasny\Auth\User;

use Jasny\Auth\ContextInterface as Context;
use Jasny\Auth\UserInterface;

/**
 * A simple user class which can be used be used instead of creating a custom user class.
 */
final class BasicUser implements UserInterface
{
    /** @var string|int */
    public $id;

    protected string $hashedPassword = '';

    /** @var string|int */
    public $role;

    /**
     * @inheritDoc
     */
    public function getAuthId(): string
    {
        return (string)$this->id;
    }

    /**
     * @inheritDoc
     */
    public function verifyPassword(string $password): bool
    {
        return password_verify($password, $this->hashedPassword);
    }

    /**
     * @inheritDoc
     */
    public function getAuthChecksum(): string
    {
        return hash('sha256', $this->id . $this->hashedPassword);
    }

    /**
     * @inheritDoc
     */
    public function getAuthRole(?Context $context = null)
    {
        return $this->role;
    }

    /**
     * @inheritDoc
     */
    public function requiresMfa(): bool
    {
        return false;
    }

    /**
     * Factory method; create object from data loaded from DB.
     *
     * @phpstan-param array<string,mixed> $data
     * @phpstan-return self
     */
    public static function fromData(array $data): self
    {
        $user = new self();

        foreach ($data as $key => $value) {
            $user->{$key} = $value;
        }

        return $user;
    }
}
