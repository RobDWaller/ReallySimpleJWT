<?php

declare(strict_types=1);

namespace ReallySimpleJWT\Encoders;

use ReallySimpleJWT\Exception\EncodeException;

/**
 * An implementation of EncodeHS256 which enforces a strong secret. This will
 * generate more secure tokens.
 */
class EncodeHS256Strong extends EncodeHS256
{
    /**
     * This class only instantiates if the secret provided is strong enough.
     */
    public function __construct(string $secret, array $options)
    {
        if (!$this->validSecret($secret, !!$options['fixed_secret_length_enabled'])) {
            throw new EncodeException('Invalid secret.', 9);
        }

        parent::__construct($secret);
    }

    /**
     * The secret should contain a number, a upper and a lowercase letter, and a
     * special character *&!@%^#$. It should be at least 12 characters in
     * length. The regex here uses lookahead assertions.
     * nonEmptyOnlyValidation is an option to only validate secret is empty or not.
     */
    private function validSecret(string $secret, bool $fixedSecretLengthEnabled = true): bool
    {
        if (!$fixedSecretLengthEnabled) {
            return !empty($secret);
        }

        if (
            !preg_match(
                '/^.*(?=.{12,}+)(?=.*\d+)(?=.*[A-Z]+)(?=.*[a-z]+)(?=.*[\*&!@%\^#\$]+).*$/',
                $secret
            )
        ) {
            return false;
        }

        return true;
    }
}
