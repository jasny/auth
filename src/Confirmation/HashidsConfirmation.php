<?php

declare(strict_types=1);

namespace Jasny\Auth\Confirmation;

use Carbon\CarbonImmutable;
use Hashids\Hashids;
use Jasny\Auth\UserInterface as User;
use Jasny\Auth\StorageInterface as Storage;
use Jasny\Immutable;
use Psr\Log\LoggerInterface as Logger;
use Psr\Log\NullLogger;

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

    /** @phpstan-var \Closure&callable(string $uid):(string|false) */
    protected \Closure $encodeUid;
    /** @phpstan-var \Closure&callable(string $uid):(string|false) */
    protected \Closure $decodeUid;

    protected Logger $logger;

    /**
     * HashidsConfirmation constructor.
     *
     * @phpstan-param string                        $secret
     * @phpstan-param null|callable(string):Hashids $createHashids
     */
    public function __construct(string $secret, ?callable $createHashids = null)
    {
        $this->secret = $secret;

        $this->createHashids = $createHashids !== null
            ? \Closure::fromCallable($createHashids)
            : fn(string $salt) => new Hashids($salt);

        $this->encodeUid = fn(string $uid) => unpack('H*', $uid)[1];
        $this->decodeUid = fn(string $hex) => pack('H*', $hex);

        $this->logger = new NullLogger();
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
     * Get a copy with custom methods to encode/decode the uid.
     *
     * @param callable $encode
     * @param callable $decode
     * @return static
     */
    public function withUidEncoded(callable $encode, callable $decode): self
    {
        return $this
            ->withProperty('encodeUid', \Closure::fromCallable($encode))
            ->withProperty('decodeUid', \Closure::fromCallable($decode));
    }

    /**
     * Get copy with logger.
     *
     * @param Logger $logger
     * @return static
     */
    public function withLogger(Logger $logger): self
    {
        return $this->withProperty('logger', $logger);
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

        $context = ['subject' => $this->subject, 'token' => self::partialToken($token)];

        if ($info === null) {
            $this->logger->debug('Invalid confirmation token', $context);
            throw new InvalidTokenException("Invalid confirmation token");
        }

        /** @var CarbonImmutable $expire */
        ['checksum' => $checksum, 'expire' => $expire, 'uid' => $uid] = $info;
        $context += ['user' => $uid, 'expire' => $expire->format('c')];

        $user = $this->fetchUserFromStorage($uid, $context);
        $this->verifyChecksum($checksum, $user, $expire, $context);
        $this->verifyNotExpired($expire, $context);

        $this->logger->info('Verified confirmation token', $context);

        return $user;
    }


    /**
     * Extract uid, expire date and checksum from hex.
     *
     * @param string $hex
     * @return null|array{checksum:string,expire:CarbonImmutable,uid:string}
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

        if ($expire->format('YmdHis') !== $expireHex) {
            return null;
        }

        return ['checksum' => $checksum, 'expire' => $expire, 'uid' => $uid];
    }

    /**
     * Encode the uid to a hex value.
     *
     * @param string $uid
     * @return string
     */
    protected function encodeUid(string $uid): string
    {
        $hex = ($this->encodeUid)($uid);

        if ($hex === false) {
            throw new \RuntimeException("Failed to encode uid");
        }

        return $hex;
    }

    /**
     * Decode the uid to a hex value.
     *
     * @param string $hex
     * @return string
     */
    protected function decodeUid(string $hex): string
    {
        $uid = ($this->decodeUid)($hex);

        if ($uid === false) {
            throw new \RuntimeException("Failed to decode uid");
        }

        return $uid;
    }

    /**
     * Fetch user from storage by uid.
     *
     * @param string   $uid
     * @param string[] $context
     * @return User
     * @throws InvalidTokenException
     */
    protected function fetchUserFromStorage(string $uid, array $context): User
    {
        $user = $this->storage->fetchUserById($uid);

        if ($user === null) {
            $this->logger->debug('Invalid confirmation token: user not available', $context);
            throw new InvalidTokenException("Token has been revoked");
        }

        return $user;
    }

    /**
     * Check that the checksum from the token matches the expected checksum.
     *
     * @param string          $checksum
     * @param User            $user
     * @param CarbonImmutable $expire
     * @param string[]        $context
     * @throws InvalidTokenException
     */
    protected function verifyChecksum(string $checksum, User $user, CarbonImmutable $expire, array $context): void
    {
        $expected = $this->calcChecksum($user, $expire);
        $expectedOld = $this->calcOldChecksum($user, $expire);

        if ($checksum === $expected || $checksum === $expectedOld) {
            return;
        }

        $this->logger->debug('Invalid confirmation token: bad checksum', $context);
        throw new InvalidTokenException("Token has been revoked");
    }

    /**
     * Check that the token isn't expired.
     *
     * @param CarbonImmutable   $expire
     * @param string[]          $context
     * @throws InvalidTokenException
     */
    protected function verifyNotExpired(CarbonImmutable $expire, array $context): void
    {
        if (!$expire->isPast()) {
            return;
        }

        $this->logger->debug('Expired confirmation token', $context);
        throw new InvalidTokenException("Token is expired");
    }


    /**
     * Calculate confirmation checksum.
     */
    protected function calcChecksum(User $user, \DateTimeInterface $expire): string
    {
        $parts = [
            CarbonImmutable::instance($expire)->utc()->format('YmdHis'),
            $user->getAuthId(),
            $user->getAuthChecksum(),
        ];

        return hash_hmac('sha256', join("\0", $parts), $this->secret);
    }

    /**
     * Calculate confirmation checksum, before switching to hmac.
     * Temporary so existing confirmation tokens will continue working. Will be removed.
     *
     * @deprecated
     */
    protected function calcOldChecksum(User $user, \DateTimeInterface $expire): string
    {
        $parts = [
            CarbonImmutable::instance($expire)->utc()->format('YmdHis'),
            $user->getAuthId(),
            $user->getAuthChecksum(),
            $this->secret,
        ];

        return hash('sha256', join("\0", $parts));
    }


    /**
     * Create a hashids service.
     */
    public function createHashids(): Hashids
    {
        $salt = hash('sha256', $this->subject . $this->secret, true);

        return ($this->createHashids)($salt);
    }

    /**
     * Create a partial token for logging.
     *
     * @param string $token
     * @return string
     */
    protected static function partialToken(string $token): string
    {
        return substr($token, 0, 8) . '...';
    }
}
