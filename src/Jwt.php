<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

use ReallySimpleJWT\Exception\JwtException;

/**
 * JWT Value object.
 *
 * Consumes a token and a secret string, used when parsing a JWT and generated
 * when creating a JWT.
 */
class Jwt
{
    /**
     * The JSON Web Token string
     */
    private string $token;

    public function __construct(string $token)
    {
        if (!$this->valid($token)) {
            throw new JwtException('Token has an invalid structure.', 1);
        }

        $this->token = $token;
    }

    /**
     * Confirm the structure of a JSON Web Token, it has three parts separated
     * by dots and complies with Base64URL standards.
     */
    private function valid(string $token): bool
    {
        return preg_match(
            '/^[a-zA-Z0-9\-\_\=]+\.[a-zA-Z0-9\-\_\=]+\.[a-zA-Z0-9\-\_\=]+$/',
            $token
        ) === 1;
    }

    /**
     * Return the JSON Web Token String
     */
    public function getToken(): string
    {
        return $this->token;
    }
}
