<?php

declare(strict_types=1);

namespace Jasny\Auth\Event;

/**
 * Trait for cancellable event
 */
trait CancellableTrait
{
    protected ?string $cancelled = null;

    /**
     * Cancel login.
     */
    public function cancel(string $reason): void
    {
        $this->cancelled = $reason;
    }

    /**
     * Is login cancelled?
     */
    public function isCancelled(): bool
    {
        return $this->cancelled !== null;
    }

    /**
     * Get reason why login was cancelled.
     */
    public function getCancellationReason(): string
    {
        return (string)$this->cancelled;
    }

    /**
     * @inheritDoc
     */
    final public function isPropagationStopped(): bool
    {
        return $this->isCancelled();
    }
}
