<?php

declare(strict_types=1);

namespace Jasny\Auth\Session;

/**
 * Use PHP sessions to store auth session info.
 */
class PhpSession implements SessionInterface
{
    protected string $key;

    /** @var \ArrayAccess<string,mixed>|null */
    protected ?\ArrayAccess $session;

    /**
     * PhpSession constructor.
     *
     * @param string $key
     * @param \ArrayAccess<string,mixed>|null $session  Omit to use $_SESSION
     */
    public function __construct(string $key = 'auth', ?\ArrayAccess $session = null)
    {
        $this->key = $key;
        $this->session = $session;
    }

    /**
     * Get the auth info from session data.
     *
     * @return array<string,mixed>
     */
    protected function getSessionData(): array
    {
        // @codeCoverageIgnoreStart
        if ($this->session === null && session_status() !== \PHP_SESSION_ACTIVE) {
            throw new \RuntimeException("Unable to get auth info from session: Session not started");
        }// @codeCoverageIgnoreEnd

        $session = $this->session ?? $_SESSION;

        return $session[$this->key] ?? [];
    }

    /**
     * Set the auth info to session data.
     *
     * @param array<string,mixed> $info
     */
    protected function setSessionData(array $info): void
    {
        if ($this->session !== null) {
            $this->session[$this->key] = $info;
        } else {
            $this->setGlobalSessionData($info); // @codeCoverageIgnore
        }
    }

    /**
     * Unset the auth info from session data.
     */
    protected function unsetSessionData(): void
    {
        if ($this->session !== null) {
            unset($this->session[$this->key]);
        } else {
            $this->setGlobalSessionData(null); // @codeCoverageIgnore
        }
    }

    /**
     * @codeCoverageIgnore
     * @internal
     *
     * @param array<string,mixed>|null $info
     */
    private function setGlobalSessionData(?array $info): void
    {
        if (session_status() !== \PHP_SESSION_ACTIVE) {
            throw new \RuntimeException("Unable to persist auth info to session: Session not started");
        }

        if ($info !== null) {
            $_SESSION[$this->key] = $info;
        } else {
            unset($_SESSION[$this->key]);
        }
    }


    /**
     * Get auth information from session.
     *
     * @return array{uid:string|int|null,context:mixed,checksum:string|null}
     */
    public function getInfo(): array
    {
        $data = $this->getSessionData();

        return [
            'uid' => $data['uid'] ?? null,
            'context' => $data['context'] ?? null,
            'checksum' => $data['checksum'] ?? null,
        ];
    }

    /**
     * Persist auth information to session.
     *
     * @param string|int  $uid
     * @param mixed       $context
     * @param string|null $checksum
     */
    public function persist($uid, $context, ?string $checksum): void
    {
        $this->setSessionData(compact('uid', 'context', 'checksum'));
    }

    /**
     * Remove auth information from session.
     */
    public function clear(): void
    {
        $this->unsetSessionData();
    }
}
