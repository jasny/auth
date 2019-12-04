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
    protected \Closure $encodeUid;
    protected Storage $storage;

    /**
     * HashidsConfirmation constructor.
     *
     * @param string                   $secret
     * @param callable(string):Hashids $createHashids
     */
    public function __construct(string $secret, ?callable $createHashids = null)
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
        $uidHex = $this->encodeUid($user->getAuthId());
        $expireHex = CarbonImmutable::instance($expire)->utc()->format('YmdHis');
        $checksum = $this->calcChecksum($user, $expire);

        return $this->createHashids()->encodeHex($checksum . $expireHex . $uidHex);
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
        $hex = $this->createHashids()->decodeHex($token);
        $info = $this->extractHex($hex);

        if ($info === null) {
            throw new InvalidTokenException('Invalid confirmation token');
        }

        /* @var CarbonImmutable $expire */
        ['checksum' => $checksum, 'expire' => $expire, 'uid' => $uid] = $info;

        if ($expire->isPast()) {
            throw new InvalidTokenException("Token is expired");
        }

        $user = $this->storage->fetchUserById($uid);
        if ($user === null) {
            throw new InvalidTokenException("User '$uid' doesn't exist");
        }

        if ($checksum !== $this->calcChecksum($user, $expire)) {
            throw new InvalidTokenException("Checksum doesn't match");
        }
        
        return $user;
    }

    /**
     * Extract uid, expire date and checksum from hex.
     *
     * @param string $hex
     * @return null|array{checksum:string,expire:CarbonImmutable,uid:string|int}
     */
    protected function extractHex(string $hex): ?array
    {
        if (strlen($hex) <= 78) {
            return null;
        }

        $checksum = substr($hex, 0, 64);
        $expireHex = substr($hex, 64, 14);
        $uidHex = substr($hex, 78);

        try {
            $uid = $this->decodeUid($uidHex);

            /** @var CarbonImmutable $expire */
            $expire = CarbonImmutable::createFromFormat('YmdHis', $expireHex, '+00:00');
        } catch (\Exception $exception) {
            return null;
        }

        return ['checksum' => $checksum, 'expire' => $expire, 'uid' => $uid];
    }

    /**
     * Encode the uid to a hex value.
     *
     * @param int|string $uid
     * @return string
     */
    protected function encodeUid($uid): string
    {
        return is_int($uid) ? '00' . dechex($uid) : '01' . (unpack('H*', $uid)[1]);
    }

    /**
     * Decode the uid to a hex value.
     *
     * @param string $hex
     * @return int|string
     */
    protected function decodeUid(string $hex)
    {
        $type = substr($hex, 0, 2);
        $uidHex = substr($hex, 2);

        if ($type !== '00' && $type !== '01') {
            throw new \RuntimeException("Invalid uid");
        }

        return $type === '00' ? (int)hexdec($uidHex) : pack('H*', $uidHex);
    }

    /**
     * Calculate confirmation checksum.
     */
    protected function calcChecksum(User $user, \DateTimeInterface $expire): string
    {
        $utc = CarbonImmutable::instance($expire)->utc();
        $parts = [$utc->format('YmdHis'), $user->getAuthId(), $user->getAuthChecksum(), $this->secret];

        return hash('sha256', join("\0", $parts));
    }


    /**
     * Create a hashids service.
     */
    public function createHashids(): Hashids
    {
        return ($this->createHashids)(hash('sha256', $this->subject . $this->secret, true));
    }
}
