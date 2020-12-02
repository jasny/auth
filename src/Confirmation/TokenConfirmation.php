<?php

declare(strict_types=1);

namespace Jasny\Auth\Confirmation;

use Jasny\Auth\StorageInterface as Storage;
use Jasny\Auth\UserInterface as User;
use Jasny\Immutable;
use Psr\Log\LoggerInterface as Logger;
use Psr\Log\NullLogger;

/**
 * Generate random confirmation tokens.
 * The random token needs to be stored to the database.
 */
class TokenConfirmation implements ConfirmationInterface
{
    use Immutable\With;

    protected int $numberOfBytes;

    /** @phpstan-param \Closure&callable(string):string */
    protected \Closure $encode;

    protected TokenStorageInterface $storage;
    protected Logger $logger;

    protected string $subject;

    /**
     * Class constructor.
     * 
     * @param int           $numberOfBytes  Number of bytes of the random string.
     * @param callable|null $encode         Method to encode random string, uses `base64_encode` by default.
     */
    public function __construct(int $numberOfBytes = 16, ?callable $encode = null)
    {
        $this->numberOfBytes = $numberOfBytes;
        $this->encode = \Closure::fromCallable($encode ?? 'base64_encode');

        $this->logger = new NullLogger();
    }

    /**
     * @inheritDoc
     */
    public function withStorage(Storage $storage): self
    {
        if (!$storage instanceof TokenStorageInterface) {
            throw new \UnexpectedValueException("Storage object needs to implement " . TokenStorageInterface::class);
        }

        return $this->withProperty('storage', $storage);
    }

    /**
     * @inheritDoc
     */
    public function withLogger(Logger $logger)
    {
        return $this->withProperty('logger', $logger);
    }

    /**
     * @inheritDoc
     */
    public function withSubject(string $subject)
    {
        return $this->withProperty('subject', $subject);
    }

    /**
     * @inheritDoc
     */
    public function getToken(User $user, \DateTimeInterface $expire): string
    {
        if (!isset($this->storage)) {
            throw new \BadMethodCallException("Storage is not set");
        }

        $rawToken = random_bytes($this->numberOfBytes);
        $token = ($this->encode)($rawToken);

        $this->storage->saveToken($user, $this->subject, $token, $expire);

        return $token;
    }

    /**
     * @inheritDoc
     */
    public function from(string $token): User
    {
        if (!isset($this->storage)) {
            throw new \BadMethodCallException("Storage is not set");
        }

        ['uid' => $uid, 'expire' => $expire] = $this->storage->fetchToken($this->subject, $token);

        if ($expire <= new \DateTime()) {
            $this->logger->debug('Expired confirmation token', ['token' => $token, 'uid' => $uid]);
            throw new InvalidTokenException("Token is expired");
        }

        $user = $this->storage->fetchUserById($uid);

        if ($user === null) {
            $this->logger->debug('Invalid confirmation token: user not available', ['token' => $token, 'uid' => $uid]);
            throw new InvalidTokenException("Token has been revoked");
        }

        return $user;
    }
}
