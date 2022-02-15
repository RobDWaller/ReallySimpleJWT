<?php

declare(strict_types=1);

namespace ReallySimpleJWT;

use ReallySimpleJWT\Exception\JwtException;

/**
 * JWT Value object which consumes a token string and ensures it is valid. It is
 * generated when creating a JWT and consumed when parsing a JWT.
 */
class Jwt
{
    private string $token;

    /**
     * Value object will only be instantiated if the JWT token string provided
     * is valid.
     */
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

    public function getToken(): string
    {
        return $this->token;
    }
}
