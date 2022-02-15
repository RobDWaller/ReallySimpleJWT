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
    public function __construct(string $secret)
    {
        if (!$this->validSecret($secret)) {
            throw new EncodeException('Invalid secret.', 9);
        }

        parent::__construct($secret);
    }

    /**
     * The secret should contain a number, a upper and a lowercase letter, and a
     * special character *&!@%^#$. It should be at least 12 characters in
     * length. The regex here uses lookahead assertions.
     */
    private function validSecret(string $secret): bool
    {
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
