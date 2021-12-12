<?php

namespace ReallySimpleJWT\Encoders;

use ReallySimpleJWT\Encoders\EncodeHS256;
use ReallySimpleJWT\Exception\EncodeException;

/**
 *
 */
class EncodeHS256Strong extends EncodeHS256
{
    public function __construct(string $secret)
    {
        if (!$this->validSecret($secret)) {
            throw new EncodeException('Invalid secret.', 9);
        }

        $this->secret = $secret;
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
                '/^.*(?=.{12,}+)(?=.*[0-9]+)(?=.*[A-Z]+)(?=.*[a-z]+)(?=.*[\*&!@%\^#\$]+).*$/',
                $secret
            )
        ) {
            return false;
        }

        return true;
    }
}