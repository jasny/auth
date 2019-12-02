<?php

declare(strict_types=1);

namespace Jasny\Auth\Confirmation;

use Carbon\CarbonImmutable;
use Hashids\Hashids;
use Jasny\Auth\UserInterface as User;
use Jasny\Auth\StorageInterface as Storage;
use Jasny\Immutable;

/**
 * Generate and verify confirmation tokens using the Hashids library.
 *
 * @link http://hashids.org/php/
 */
class HashidsConfirmation implements ConfirmationInterface
{
    use Immutable\With;

    protected int $confirmLength;
    protected string $subject;

    protected \Closure $createHashids;
    protected Storage $storage;

    /**
     * HashidsConfirmation constructor.
     *
     * @param callable(string):Hashids $createHashids
     * @param int                      $confirmLength
     */
    public function __construct(callable $createHashids, int $confirmLength = 24)
    {
        $this->createHashids = \Closure::fromCallable($createHashids);
        $this->confirmLength = $confirmLength;
    }

    /**
     * Get copy with storage service.
     *
     * @param Storage $storage
     * @return static
     */
    public function withStorage(Storage $storage): self
    {
        return $this->withProperty('storage', $storage);
    }

    /**
     * Create a copy of this service with a specific subject.
     *
     * @param string $subject
     * @return static
     */
    public function withSubject(string $subject): self
    {
        return $this->withProperty('subject', $subject);
    }


    /**
     * Generate a confirmation token.
     */
    public function getToken(User $user, \DateTimeInterface $expire): string
    {
        $uid = (string)$user->getId();
        $date = $expire->format('YmdHisO');
        $checksum = $this->calcConfirmChecksum($uid, $date, $user->getAuthChecksum());

        return $this->createHashids()->encodeHex(join("\n", [$checksum, $date, $uid]));
    }

    /**
     * Get user by confirmation token.
     *
     * @param string $token Confirmation token
     * @return User
     * @throws InvalidTokenException
     */
    public function from(string $token): User
    {
        $combined = $this->createHashids()->decodeHex($token);

        if (preg_match(sprintf('/^[0-9a-f]{%d}\n\d{14}[+-]\d{4}\n.+$/', $this->confirmLength), $combined) === 0) {
            throw new InvalidTokenException('Invalid confirmation token');
        }

        [$confirm, $date, $uid] = explode("\n", $combined, 3) + ['', '', ''];

        $this->assertNotExpired($date);

        $user = $this->storage->fetchUserById($uid);

        if ($user === null) {
            throw new InvalidTokenException("User '$uid' doesn't exist");
        }

        if ($confirm !== $this->calcConfirmChecksum($uid, $date, $user->getAuthChecksum())) {
            throw new InvalidTokenException("Checksum doesn't match");
        }
        
        return $user;
    }

    /**
     * Create a hashids service.
     */
    protected function createHashids(): Hashids
    {
        return ($this->createHashids)($this->subject);
    }

    /**
     * Calculate confirmation checksum.
     */
    protected function calcConfirmChecksum(string $uid, string $date, string $chk): string
    {
        return substr(hash('sha256', $uid . $date . $chk), 0, $this->confirmLength);
    }

    /**
     * Assert token isn't expired.
     *
     * @throws InvalidTokenException
     */
    protected function assertNotExpired(string $date): void
    {
        try {
            $expire = CarbonImmutable::createFromFormat('YmdHisO', $date);
        } catch (\Exception $exception) {
            throw new InvalidTokenException("Token date is invalid", 0, $exception);
        }

        if ($expire === false || $expire->isPast()) {
            throw new InvalidTokenException("Token is expired");
        }
    }
}
