<?php

declare(strict_types=1);

namespace Jasny\Auth\Confirmation;

use Carbon\CarbonImmutable;
use DateTimeImmutable;
use DateTimeInterface;
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

    protected string $subject;
    protected string $secret;

    protected \Closure $createHashids;
    protected Storage $storage;

    /**
     * HashidsConfirmation constructor.
     *
     * @param string                   $secret
     * @param callable(string):Hashids $createHashids
     */
    public function __construct(string $secret, ?callable $createHashids)
    {
        $this->secret = $secret;

        $this->createHashids = $createHashids !== null
            ? \Closure::fromCallable($createHashids)
            : fn(string $salt) => new Hashids($salt);
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
        $packedDate = $this->packDate($expire);
        $checksum = $this->calcChecksum($packedDate, $uid, $user->getAuthChecksum());

        return $this->createHashids()->encodeHex($checksum . $packedDate . $uid);
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
        $packed = $this->createHashids()->decodeHex($token);
        $info = strlen($packed) > 38 ? unpack('Ndate/Ntime/a*uid', $packed, 32) : false;

        if ($info === false) {
            throw new InvalidTokenException('Invalid confirmation token');
        }

        $uid = $info['uid'];
        $checksum = substr($packed, 0, 32);
        $packedDate = substr($packed, 32, 8);

        $this->assertNotExpired($info['date'], $info['time']);

        $user = $this->storage->fetchUserById($uid);

        if ($user === null) {
            throw new InvalidTokenException("User '$uid' doesn't exist");
        }

        if ($checksum !== $this->calcChecksum($packedDate, $uid, $user->getAuthChecksum())) {
            throw new InvalidTokenException("Checksum doesn't match");
        }
        
        return $user;
    }

    /**
     * Turn date into binary value.
     */
    protected function packDate(\DateTimeInterface $date): string
    {
        $utc = CarbonImmutable::instance($date)->utc();

        $dateNumber = (int)$utc->format('Ymd');
        $timeNumber = (int)$utc->format('His');

        return pack('NN', $dateNumber, $timeNumber);
    }

    /**
     * Create a hashids service.
     */
    public function createHashids(): Hashids
    {
        return ($this->createHashids)(hash('sha256', $this->subject . $this->secret, true));
    }

    /**
     * Calculate confirmation checksum.
     */
    protected function calcChecksum(string $packedDate, string $uid, string $chk): string
    {
        return hash('sha256', $packedDate . $uid . $chk . $this->secret, true);
    }

    /**
     * Assert token isn't expired.
     *
     * @throws InvalidTokenException
     */
    protected function assertNotExpired(int $dateNumber, int $timeNumber): void
    {
        try {
            $dateString = sprintf("%'08d %'06d+0000", $dateNumber, $timeNumber);
            $expire = CarbonImmutable::createFromFormat('Ymd HisO', $dateString);
        } catch (\Exception $exception) {
            throw new InvalidTokenException("Token expiration date is invalid", 0, $exception);
        }

        if ($expire === false || $expire->isPast()) {
            throw new InvalidTokenException("Token is expired");
        }
    }
}
