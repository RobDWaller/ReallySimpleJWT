<?php

namespace ReallySimpleJWT\Interfaces;

/**
 * Interface for Secret classes, enables custom secret validation.
 */
interface Secret
{
    /**
     * Validate the provided signature secret.
     *
     * @see Secret::validate()
     */
    public function validate(string $secret): bool;
}
